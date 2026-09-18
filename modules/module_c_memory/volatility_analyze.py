"""Structural analysis of an acquired memory image via Volatility3 (subprocess wrapper).

Complements analyzer.py's string carving: analyzer.py scans raw bytes for text patterns
and has no idea which process (if any) a hit belongs to, or when that process ran.
Volatility3 parses OS kernel data structures instead -- process pool allocations, network
state, open file handles -- so it can answer "which process, and when" in cases string
carving can't, at the cost of needing intact/compatible kernel symbols for the imaged OS
(string carving needs neither). This is a second, independent analysis path over the same
acquired image, not a replacement for the string carver and not a second detection engine
layered on top of it -- see the "source" tag on every row this module returns.

Notably, windows.psscan finds residual _EPROCESS pool allocations even after a process
has exited (CreateTime *and* ExitTime survive in that allocation until it's reused),
which is exactly the gap winpmem_acquire.py's full-memory acquisition path exists to
fill -- see that module's docstring.

This wraps Volatility3's `vol` CLI as a subprocess (`vol -f <image> -r json <plugin>`)
rather than driving its internal framework/context/config API directly, so this module
stays a thin, easily-testable process wrapper instead of reimplementing Volatility3's
symbol-table plumbing. Unlike dumper.py/winpmem_acquire.py, there is no Windows-only
import to guard here: Volatility3 is a pure-Python analysis tool that runs on any host OS
against a Windows memory image (that cross-platform "analyze on Linux, image came from
Windows" split is the normal real-world workflow) -- the platform constraint lives in the
*image's* OS, not in this module or the vol3 CLI.

Every plugin call is independent and best-effort: one plugin's failure (commonly: no
symbol table matching the imaged OS build, or an image too small/wrong-shaped for a given
plugin) is recorded and skipped, never aborts the rest. Only a failure to invoke
Volatility3 at all -- binary not found, image path unreadable -- raises AnalysisError.
"""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
from collections.abc import Sequence
from datetime import datetime, timezone
from pathlib import Path

from core.exceptions import AnalysisError

# The five plugins this task wires up. windows.psscan and windows.netscan are pool-scan
# based, so (unlike windows.pslist/windows.netstat) they can still find processes/
# connections whose owning structures have since been torn down -- the same
# "already-exited process" scenario winpmem_acquire.py's full-memory capture targets.
PLUGINS: tuple[str, ...] = (
    "windows.psscan.PsScan",
    "windows.netscan.NetScan",
    "windows.filescan.FileScan",
    "windows.cmdline.CmdLine",
    "windows.registry.hivelist.HiveList",
)

DEFAULT_VOL_BIN = "vol"
# A full-system image can take a long time per plugin (pool scanning walks the whole
# physical layer); bounded rather than unbounded so one hung/thrashing plugin doesn't
# block the rest of the run forever.
PLUGIN_TIMEOUT_SECONDS = 1800

# Volatility3's JSON renderer wraps every row in a tree-node shape and always adds this
# key, empty for the flat (non-nested) plugins used here -- a renderer artifact, not
# plugin data, so it's dropped during normalization rather than passed through.
_TREE_ARTIFACT_KEY = "__children"


def _resolve_vol_binary(vol_path: Path | str | None) -> str:
    """Return a path/name subprocess can exec, or raise if it plainly can't be found.

    A relative/bare name (the default, "vol") is left to $PATH -- shutil.which() confirms
    it resolves now so a bad install is reported clearly instead of via a generic
    FileNotFoundError once a plugin actually runs.
    """
    candidate = str(vol_path) if vol_path else DEFAULT_VOL_BIN
    resolved = shutil.which(candidate)
    if resolved is None:
        raise AnalysisError(
            f"Volatility3 CLI not found: {candidate!r}. Install it (pip install volatility3) "
            "or pass --vol-path pointing at the vol/vol.exe entry point."
        )
    return resolved


def run_plugin(
    vol_bin: str, image_path: Path, plugin: str, timeout: int = PLUGIN_TIMEOUT_SECONDS
) -> subprocess.CompletedProcess[str]:
    """Run one Volatility3 plugin against `image_path` with the JSON renderer.

    Returns the CompletedProcess unconditionally -- a non-zero exit or unparseable
    stdout is Volatility3's normal way of reporting "this plugin doesn't fit this image"
    (e.g. no matching symbol table) and is the caller's job to record per-plugin, not an
    invocation failure of this wrapper.
    """
    cmd = [vol_bin, "-q", "-f", str(image_path), "-r", "json", plugin]
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired as exc:
        return subprocess.CompletedProcess(
            cmd, returncode=-1, stdout="", stderr=f"timed out after {timeout}s: {exc}"
        )


def _normalize_rows(raw_rows: list[dict], plugin: str) -> list[dict]:
    """Light, uniform normalization only -- strip the JSON renderer's tree-node
    artifact and stamp provenance. Column names/values are passed through exactly as
    Volatility3 produced them; this is a structural-facts pass, not a second detection
    engine reinterpreting what the plugin found.
    """
    source = f"volatility3:{plugin}"
    normalized = []
    for row in raw_rows:
        row = {k: v for k, v in row.items() if k != _TREE_ARTIFACT_KEY}
        row["source"] = source
        normalized.append(row)
    return normalized


def _run_one(vol_bin: str, image_path: Path, plugin: str) -> dict:
    result = run_plugin(vol_bin, image_path, plugin)
    if result.returncode != 0:
        return {
            "status": "error",
            "message": (result.stderr or result.stdout or f"exit code {result.returncode}").strip()[
                :2000
            ],
            "rows": [],
            "row_count": 0,
        }
    try:
        rows = json.loads(result.stdout)
        if not isinstance(rows, list):
            raise ValueError(f"expected a JSON array, got {type(rows).__name__}")
    except (json.JSONDecodeError, ValueError) as exc:
        return {
            "status": "error",
            "message": f"could not parse Volatility3 JSON output: {exc}",
            "rows": [],
            "row_count": 0,
        }
    rows = _normalize_rows(rows, plugin)
    return {"status": "ok", "message": None, "rows": rows, "row_count": len(rows)}


def analyze(
    image_path: Path,
    vol_path: Path | str | None = None,
    plugins: Sequence[str] = PLUGINS,
) -> dict:
    """Run each plugin in `plugins` against `image_path`; never raises for a single
    plugin's failure, only for being unable to attempt any of them at all."""
    if not image_path.exists():
        raise AnalysisError(f"Image not found: {image_path}")
    vol_bin = _resolve_vol_binary(vol_path)

    plugin_results = {plugin: _run_one(vol_bin, image_path, plugin) for plugin in plugins}
    return {
        "vol_bin": vol_bin,
        "image": str(image_path),
        "plugins": plugin_results,
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }


def find_process_pid(vol_bin: str, image_path: Path, process_name: str = "firefox.exe") -> dict:
    """Discover which PID(s) `process_name` has in `image_path`, via windows.pslist.

    Deliberately pslist, not psscan, even though psscan is one of the five plugins
    analyze() runs above: windows.memmap.Memmap (see extract_process_memory) builds its
    per-process view by calling pslist.PsList.list_processes() internally (confirmed by
    reading the installed Volatility3 source), so a PID psscan finds via its pool-scan
    but that pslist's live kernel-list walk no longer sees -- i.e. one that has already
    exited -- cannot be extracted by memmap regardless of what this function returns.
    psscan is still the right tool to *confirm a since-exited process existed at all*
    (see analyze()'s windows.psscan.PsScan pass); it just can't feed memmap.
    """
    result = _run_one(vol_bin, image_path, "windows.pslist.PsList")
    if result["status"] != "ok":
        return {
            "status": "error",
            "message": f"windows.pslist failed: {result['message']}",
            "candidates": [],
            "chosen_pid": None,
            "chosen_reason": None,
        }
    candidates = [
        r for r in result["rows"] if (r.get("ImageFileName") or "").lower() == process_name.lower()
    ]
    if not candidates:
        return {
            "status": "not_found",
            "message": f"No live {process_name} process visible to windows.pslist -- it may have already "
            "exited by capture time (memmap can only extract a still-live process's pages; check "
            "windows.psscan for a residual/exited entry instead, which proves existence/timing but not "
            "content).",
            "candidates": [],
            "chosen_pid": None,
            "chosen_reason": None,
        }
    # Firefox's multi-process architecture spawns content-process children with the main
    # UI process's PID as their PPID, so the main process -- the one actually holding
    # browsing-relevant memory -- is identifiable as whichever candidate is itself a
    # parent of another same-named candidate. Falls back to the lowest PID (oldest, by
    # PID-allocation convention) if that relationship isn't found, e.g. a single instance.
    candidate_pids = {c["PID"] for c in candidates}
    parent_pids = {
        c["PID"] for c in candidates if c["PID"] in {c2.get("PPID") for c2 in candidates}
    }
    if parent_pids:
        chosen, reason = min(parent_pids), "parent of other same-named child processes"
    else:
        chosen, reason = (
            min(candidate_pids),
            "lowest PID (no parent/child relationship among candidates)",
        )
    return {
        "status": "ok",
        "message": None,
        "candidates": candidates,
        "chosen_pid": chosen,
        "chosen_reason": reason,
    }


def extract_process_memory(
    vol_bin: str,
    image_path: Path,
    pid: int,
    output_dir: Path,
    timeout: int = PLUGIN_TIMEOUT_SECONDS,
) -> Path:
    """Extract one process's resident pages from a full-memory image via
    `windows.memmap --pid <pid> --dump`, writing `pid.<pid>.dmp` under `output_dir`
    (Volatility3's own naming convention for this plugin -- see its source). Only
    succeeds if `pid` is still visible to windows.pslist at capture time; see
    find_process_pid()'s docstring for why an exited process can't be extracted this way.
    """
    output_dir.mkdir(parents=True, exist_ok=True)
    cmd = [
        vol_bin,
        "-q",
        "-o",
        str(output_dir),
        "-f",
        str(image_path),
        "-r",
        "json",
        "windows.memmap.Memmap",
        "--pid",
        str(pid),
        "--dump",
    ]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired as exc:
        raise AnalysisError(
            f"windows.memmap timed out after {timeout}s extracting PID {pid}: {exc}"
        ) from exc
    if result.returncode != 0:
        raise AnalysisError(
            f"windows.memmap failed for PID {pid} (exit {result.returncode}).\n"
            f"--- stdout ---\n{result.stdout}\n--- stderr ---\n{result.stderr}"
        )
    dump_path = output_dir / f"pid.{pid}.dmp"
    if not dump_path.exists() or dump_path.stat().st_size == 0:
        raise AnalysisError(
            f"windows.memmap reported success but produced no (or an empty) {dump_path.name} -- PID {pid} "
            "may have exited between discovery and extraction, or its pages could not be read."
        )
    return dump_path


def extract_target_process(
    vol_path: Path | str | None,
    image_path: Path,
    output_dir: Path,
    process_name: str = "firefox.exe",
    pid: int | None = None,
) -> dict:
    """Best-effort discover-then-extract: find `process_name`'s PID (unless `pid` is
    given explicitly) and pull just its resident pages out of a full-memory image, so
    analyzer.py's string carver can run against that far smaller, far less noisy extract
    instead of the whole image.

    Returns a dict describing the outcome -- status "ok"/"not_found"/"error" -- and never
    raises for a normal "couldn't extract" outcome (the caller is expected to fall back
    to analyzing the full image, which still works and still finds real evidence). Only
    raises AnalysisError if Volatility3 itself can't be invoked at all or the source
    image is missing, matching analyze()'s own contract.
    """
    if not image_path.exists():
        raise AnalysisError(f"Image not found: {image_path}")
    vol_bin = _resolve_vol_binary(vol_path)

    if pid is not None:
        discovery = {
            "status": "ok",
            "message": None,
            "candidates": [],
            "chosen_pid": pid,
            "chosen_reason": "explicit PID override",
        }
    else:
        discovery = find_process_pid(vol_bin, image_path, process_name)
        if discovery["status"] != "ok":
            return {
                "status": discovery["status"],
                "message": discovery["message"],
                "discovery": discovery,
                "source_image": str(image_path),
                "dump_path": None,
            }
        pid = discovery["chosen_pid"]

    try:
        dump_path = extract_process_memory(vol_bin, image_path, pid, output_dir)
    except AnalysisError as exc:
        return {
            "status": "error",
            "message": str(exc),
            "discovery": discovery,
            "source_image": str(image_path),
            "dump_path": None,
        }
    return {
        "status": "ok",
        "message": None,
        "discovery": discovery,
        "source_image": str(image_path),
        "pid": pid,
        "dump_path": str(dump_path),
    }


def format_summary(report: dict) -> str:
    lines = [
        "=== TRANCE Volatility3 Structural Analysis ===",
        f"Image: {report['image']}",
        f"vol binary: {report['vol_bin']}",
        "",
    ]
    for plugin, result in report["plugins"].items():
        if result["status"] == "ok":
            lines.append(f"--- {plugin}: {result['row_count']} row(s) ---")
        else:
            lines.append(f"--- {plugin}: FAILED — {result['message']} ---")
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Run Volatility3's structural plugins (psscan/netscan/filescan/cmdline/hivelist) "
        "against an acquired memory image and emit a JSON report."
    )
    parser.add_argument("image", type=Path, help="Path to the memory image (.bin/.raw)")
    parser.add_argument(
        "--vol-path",
        help=f"Path to the Volatility3 'vol' entry point (default: {DEFAULT_VOL_BIN!r} on $PATH)",
    )
    parser.add_argument(
        "--output", type=Path, help="Path for the JSON report (default: <image>.vol3.json)"
    )
    args = parser.parse_args()

    try:
        report = analyze(args.image, args.vol_path)
    except AnalysisError as exc:
        print(f"[!] {exc}", file=sys.stderr)
        sys.exit(1)

    output_path = args.output or args.image.with_name(args.image.name + ".vol3.json")
    output_path.write_text(json.dumps(report, indent=2))
    print(format_summary(report))
    print(f"\n[*] JSON report written to {output_path}")


if __name__ == "__main__":
    main()
