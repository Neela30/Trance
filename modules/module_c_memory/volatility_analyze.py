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
from datetime import datetime, timezone
from pathlib import Path
from typing import Sequence

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
            "message": (result.stderr or result.stdout or f"exit code {result.returncode}").strip()[:2000],
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
        "--vol-path", help=f"Path to the Volatility3 'vol' entry point (default: {DEFAULT_VOL_BIN!r} on $PATH)"
    )
    parser.add_argument("--output", type=Path, help="Path for the JSON report (default: <image>.vol3.json)")
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
