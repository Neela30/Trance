"""TRANCE folder-aware analyze entry point: point at an acquire_all.py evidence
folder and get the same findings.json/report.html/custody.json main.py produces.

    python analyze_evidence.py --case demo --evidence-dir evidence \\
        --onion <address>.onion --host 127.0.0.1:5000 --username alice

Thin wrapper, not a second pipeline: resolves each artifact's concrete path
(from --evidence-dir's acquire_manifest.json, written by acquire_all.py, or
by best-effort filename globbing if no manifest is present -- so a hand-built
evidence folder still works) and calls main.main() with the equivalent argv.
Any of main.py's own flags passed explicitly here always win over
auto-discovery, so this stays a convenience layer, not a second source of
truth for the pipeline itself.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path, PureWindowsPath

import main as main_module

# main.py's --source-type default; used when a manifest doesn't say otherwise.
_DEFAULT_SOURCE_TYPE = "process"


def _latest(paths: list[Path]) -> Path | None:
    return max(paths, key=lambda p: p.stat().st_mtime) if paths else None


def _rebase_onto(evidence_dir: Path, recorded: str) -> str:
    """Map a manifest path onto wherever the evidence folder lives *now*.

    The manifest was written on the target, so a recorded path may be relative to the
    acquire-time working directory ("evidence\\registry\\SYSTEM_..."), absolute on the
    target ("C:\\forensics\\...\\evidence\\registry\\SYSTEM_..."), or already relative to
    the evidence folder ("registry/SYSTEM_..."), and use Windows separators either way.
    None of those resolve as-is once the folder is copied to the examiner's machine, so
    take the longest trailing run of components that exists under evidence_dir. If
    nothing exists, fall back to the full relative form so main.py reports a clear
    file-not-found against the evidence folder rather than some unrelated CWD.
    """
    parts = [p for p in PureWindowsPath(recorded).parts if p not in ("\\", "/")]
    parts = [p for p in parts if not PureWindowsPath(p).drive]
    for start in range(len(parts)):
        candidate = evidence_dir.joinpath(*parts[start:])
        if candidate.exists():
            return str(candidate)
    return str(evidence_dir.joinpath(*parts)) if parts else str(evidence_dir)


def _resolve_from_manifest(evidence_dir: Path, manifest: dict) -> dict:
    resolved: dict[str, str] = {}

    def ok_path(entry: object) -> str | None:
        if isinstance(entry, dict) and entry.get("status") == "ok" and entry.get("path"):
            return _rebase_onto(evidence_dir, entry["path"])
        return None

    registry = manifest.get("registry", {})
    for key, flag in (
        ("SYSTEM", "system"),
        ("NTUSER.DAT", "ntuser"),
        ("Amcache.hve", "amcache"),
        ("SOFTWARE", "software"),
    ):
        path = ok_path(registry.get(key))
        if path:
            resolved[flag] = path

    memory = manifest.get("memory", {})
    full_image = memory.get("full_image", {})
    live_dump = memory.get("live_dump", {})
    if path := ok_path(full_image):
        resolved["dump"] = path
        resolved["source_type"] = full_image.get("source_type", "full-memory")
    elif path := ok_path(live_dump):
        resolved["dump"] = path
        resolved["source_type"] = live_dump.get("source_type", _DEFAULT_SOURCE_TYPE)

    disk = manifest.get("disk", {})
    if path := ok_path(disk.get("profile")):
        resolved["disk_profile"] = path
    if path := ok_path(disk.get("tor_dir")):
        resolved["tor_dir"] = path

    return resolved


def _resolve_by_globbing(evidence_dir: Path) -> dict:
    """acquire_all.py's registry/memory/disk subfolder layout is preferred; falls back
    to evidence_dir itself for a flat folder (e.g. registry/memory acquire scripts run
    directly and copied off a VM as-is, predating acquire_all.py, or hand-assembled) --
    same filename patterns, just not sorted into subfolders."""
    resolved: dict[str, str] = {}

    registry_dir = evidence_dir / "registry"
    if not registry_dir.is_dir():
        registry_dir = evidence_dir
    for pattern, flag in (
        ("SYSTEM_*", "system"),
        ("NTUSER_*.DAT", "ntuser"),
        ("Amcache_*.hve", "amcache"),
        ("SOFTWARE_*", "software"),
    ):
        match = _latest([p for p in registry_dir.glob(pattern) if p.suffix != ".sha256"])
        if match:
            resolved[flag] = str(match)

    memory_dir = evidence_dir / "memory"
    if not memory_dir.is_dir():
        memory_dir = evidence_dir
    full_image = _latest(list(memory_dir.glob("fullmem_*.raw")))
    live_dump = _latest(list(memory_dir.glob("firefox_*.bin")))
    if full_image:
        resolved["dump"] = str(full_image)
        resolved["source_type"] = "full-memory"
    elif live_dump:
        resolved["dump"] = str(live_dump)
        resolved["source_type"] = _DEFAULT_SOURCE_TYPE

    disk_profile = evidence_dir / "disk" / "profile"
    if disk_profile.is_dir():
        resolved["disk_profile"] = str(disk_profile)
    tor_dir = evidence_dir / "disk" / "tor_dir"
    if tor_dir.is_dir():
        resolved["tor_dir"] = str(tor_dir)

    return resolved


def resolve_evidence(evidence_dir: Path) -> dict:
    manifest_path = evidence_dir / "acquire_manifest.json"
    if manifest_path.is_file():
        manifest = json.loads(manifest_path.read_text())
        return _resolve_from_manifest(evidence_dir, manifest)
    return _resolve_by_globbing(evidence_dir)


def build_argv(args: argparse.Namespace, resolved: dict) -> list[str]:
    argv = ["--case", args.case, "--output-dir", str(args.output_dir)]
    if args.evidence_dir:
        argv += ["--evidence-dir", str(args.evidence_dir)]
    if args.verbose:
        argv.append("--verbose")
    if args.report_timezone:
        argv += ["--report-timezone", args.report_timezone]

    overrides = {
        "ntuser": args.ntuser,
        "system": args.system,
        "amcache": args.amcache,
        "software": args.software,
        "disk_profile": args.disk_profile,
        "tor_dir": args.tor_dir,
        "dump": args.dump,
        "source_type": args.source_type,
    }
    flag_names = {
        "ntuser": "--ntuser",
        "system": "--system",
        "amcache": "--amcache",
        "software": "--software",
        "disk_profile": "--disk-profile",
        "tor_dir": "--tor-dir",
        "dump": "--dump",
        "source_type": "--source-type",
    }
    for key, flag in flag_names.items():
        value = overrides[key] if overrides[key] is not None else resolved.get(key)
        if value:
            argv += [flag, str(value)]

    if args.disk_image:
        argv += ["--disk-image", str(args.disk_image)]
    if args.disk_root:
        argv += ["--disk-root", str(args.disk_root)]
    for flag, value in (
        ("--onion", args.onion),
        ("--host", args.host),
        ("--username", args.username),
        ("--vol3-path", args.vol3_path),
        ("--vol3-extract-process", args.vol3_extract_process),
    ):
        if value:
            argv += [flag, value]
    if args.vol3_extract_pid is not None:
        argv += ["--vol3-extract-pid", str(args.vol3_extract_pid)]
    return argv


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Analyze an acquire_all.py evidence folder and produce the TRANCE case report."
    )
    parser.add_argument("--case", required=True, help="Case name; passed through to main.py")
    parser.add_argument("--output-dir", type=Path, default=Path("output"))
    parser.add_argument(
        "--evidence-dir",
        type=Path,
        help="acquire_all.py output folder (or any folder with the same registry/memory/disk "
        "layout); used both for auto-discovery and as findings.json provenance",
    )
    parser.add_argument("--verbose", action="store_true")
    parser.add_argument(
        "--report-timezone",
        help="IANA zone name (e.g. Asia/Colombo) for the report's local-time display; "
        "passed through to main.py. Omit to auto-detect this machine's own timezone",
    )

    parser.add_argument("--ntuser", type=Path, help="Override auto-discovery")
    parser.add_argument("--system", type=Path, help="Override auto-discovery")
    parser.add_argument("--amcache", type=Path, help="Override auto-discovery")
    parser.add_argument("--software", type=Path, help="Override auto-discovery")
    parser.add_argument("--disk-profile", type=Path, help="Override auto-discovery")
    parser.add_argument("--tor-dir", type=Path, help="Override auto-discovery")
    parser.add_argument("--disk-image", type=Path, help="Raw image to carve (not auto-discovered)")
    parser.add_argument(
        "--disk-root",
        type=Path,
        help="Root of a read-only mounted Windows volume for Zone.Identifier/NTFS-journal "
        "carving (not auto-discovered)",
    )
    parser.add_argument("--dump", type=Path, help="Override auto-discovery")
    parser.add_argument("--source-type", choices=("process", "full-memory"), default=None)

    parser.add_argument("--onion")
    parser.add_argument("--host")
    parser.add_argument("--username")
    parser.add_argument("--vol3-path")
    parser.add_argument("--vol3-extract-process")
    parser.add_argument("--vol3-extract-pid", type=int)

    args = parser.parse_args(argv)

    resolved = resolve_evidence(args.evidence_dir) if args.evidence_dir else {}
    main_argv = build_argv(args, resolved)
    return main_module.main(main_argv)


if __name__ == "__main__":
    sys.exit(main())
