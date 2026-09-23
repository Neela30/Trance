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
from pathlib import Path

import main as main_module

# main.py's --source-type default; used when a manifest doesn't say otherwise.
_DEFAULT_SOURCE_TYPE = "process"


def _latest(paths: list[Path]) -> Path | None:
    return max(paths, key=lambda p: p.stat().st_mtime) if paths else None


def _resolve_from_manifest(evidence_dir: Path, manifest: dict) -> dict:
    resolved: dict[str, str] = {}

    registry = manifest.get("registry", {})
    for key, flag in (("SYSTEM", "system"), ("NTUSER.DAT", "ntuser"), ("Amcache.hve", "amcache")):
        entry = registry.get(key)
        if isinstance(entry, dict) and entry.get("status") == "ok" and entry.get("path"):
            resolved[flag] = entry["path"]

    memory = manifest.get("memory", {})
    full_image = memory.get("full_image", {})
    live_dump = memory.get("live_dump", {})
    if isinstance(full_image, dict) and full_image.get("status") == "ok":
        resolved["dump"] = full_image["path"]
        resolved["source_type"] = full_image.get("source_type", "full-memory")
    elif isinstance(live_dump, dict) and live_dump.get("status") == "ok":
        resolved["dump"] = live_dump["path"]
        resolved["source_type"] = live_dump.get("source_type", _DEFAULT_SOURCE_TYPE)

    disk = manifest.get("disk", {})
    profile = disk.get("profile", {})
    tor_dir = disk.get("tor_dir", {})
    if isinstance(profile, dict) and profile.get("status") == "ok" and profile.get("path"):
        resolved["disk_profile"] = profile["path"]
    if isinstance(tor_dir, dict) and tor_dir.get("status") == "ok" and tor_dir.get("path"):
        resolved["tor_dir"] = tor_dir["path"]

    return resolved


def _resolve_by_globbing(evidence_dir: Path) -> dict:
    resolved: dict[str, str] = {}

    registry_dir = evidence_dir / "registry"
    if registry_dir.is_dir():
        for pattern, flag in (
            ("SYSTEM_*", "system"),
            ("NTUSER_*.DAT", "ntuser"),
            ("Amcache_*.hve", "amcache"),
        ):
            match = _latest(list(registry_dir.glob(pattern)))
            if match:
                resolved[flag] = str(match)

    memory_dir = evidence_dir / "memory"
    if memory_dir.is_dir():
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

    overrides = {
        "ntuser": args.ntuser,
        "system": args.system,
        "amcache": args.amcache,
        "disk_profile": args.disk_profile,
        "tor_dir": args.tor_dir,
        "dump": args.dump,
        "source_type": args.source_type,
    }
    flag_names = {
        "ntuser": "--ntuser",
        "system": "--system",
        "amcache": "--amcache",
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

    parser.add_argument("--ntuser", type=Path, help="Override auto-discovery")
    parser.add_argument("--system", type=Path, help="Override auto-discovery")
    parser.add_argument("--amcache", type=Path, help="Override auto-discovery")
    parser.add_argument("--disk-profile", type=Path, help="Override auto-discovery")
    parser.add_argument("--tor-dir", type=Path, help="Override auto-discovery")
    parser.add_argument("--disk-image", type=Path, help="Raw image to carve (not auto-discovered)")
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
