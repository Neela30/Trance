"""TRANCE combined acquire entry point: run every acquisition step into one
evidence folder on a live Windows target (elevated).

    python acquire_all.py --output-dir evidence

Disk evidence doesn't need --tor-browser-dir pointed at it -- omit it and
this auto-discovers a Tor Browser install by scanning the filesystem (home
directory/Desktop/Downloads/Documents, then every drive) for its install
signature. Pass --tor-browser-dir explicitly to skip the scan when you
already know where it is.

Full-memory capture works the same way: omit --winpmem-path and this scans
for a WinPMEM binary instead of requiring it up front, and always attempts
the full-image capture alongside the live process dump -- the live dump
only ever captures a *running* firefox.exe, so it's not a substitute for
the full-image path when Tor Browser has already exited.

Writes <output-dir>/{registry,memory,disk}/... and <output-dir>/
acquire_manifest.json -- the contract analyze_evidence.py reads to resolve
each artifact's path without the examiner having to type them all by hand.

Registry (SYSTEM/NTUSER/Amcache/SOFTWARE/UsrClass.dat) and the live memory dump need an elevated
session; the disk copy doesn't but runs alongside them here for one output
folder. Each category is isolated -- one failing does not stop the others,
same philosophy as every acquire.acquire_all() this wraps.
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

from core.exceptions import AcquisitionError
from core.winadmin import is_admin
from modules.module_a_registry import acquire as registry_acquire
from modules.module_b_disk import acquire as disk_acquire
from modules.module_c_memory import dumper as memory_dumper
from modules.module_c_memory import winpmem_acquire


def _acquire_registry(output_dir: Path, ntuser_user: str | None) -> dict:
    try:
        return registry_acquire.acquire_all(output_dir / "registry", ntuser_user=ntuser_user)
    except AcquisitionError as exc:
        return {"status": "error", "message": str(exc)}


def _acquire_memory(output_dir: Path, winpmem_path: Path | None) -> dict:
    """Both paths are always attempted, independently -- the live dump only ever
    captures a *running* firefox.exe, so it tells you nothing about whether Tor
    Browser already exited; the full-image capture is the one that still works either
    way, so it isn't gated on the live dump's outcome."""
    result: dict = {}
    try:
        dump_path = memory_dumper.acquire(output_dir / "memory")
        result["live_dump"] = {"status": "ok", "path": str(dump_path), "source_type": "process"}
    except AcquisitionError as exc:
        result["live_dump"] = {"status": "error", "message": str(exc)}

    if winpmem_path is None:
        candidates = winpmem_acquire.find_winpmem_binaries()
        if candidates:
            winpmem_path = candidates[0]
            if len(candidates) > 1:
                result["other_winpmem_binaries_found"] = [str(p) for p in candidates[1:]]

    if winpmem_path is not None:
        try:
            image_path = winpmem_acquire.acquire(winpmem_path, output_dir / "memory")
            result["full_image"] = {
                "status": "ok",
                "path": str(image_path),
                "source_type": "full-memory",
                "winpmem_path": str(winpmem_path),
            }
        except AcquisitionError as exc:
            result["full_image"] = {"status": "error", "message": str(exc)}
    else:
        result["full_image"] = {
            "status": "skipped",
            "message": "no --winpmem-path supplied and none found automatically",
        }
    return result


def _acquire_disk(
    output_dir: Path,
    tor_browser_dir: Path | None,
    disk_profile_src: Path | None,
    tor_dir_src: Path | None,
) -> dict:
    """No path given at all isn't treated as "nothing to do" -- disk_acquire.acquire_all()
    auto-discovers a Tor Browser install by scanning the filesystem in that case (see
    modules/module_b_disk/acquire.py), so this always attempts the step and only reports
    "error" if that scan genuinely finds nothing."""
    try:
        return disk_acquire.acquire_all(
            tor_browser_dir=tor_browser_dir,
            profile_src=disk_profile_src,
            tor_dir_src=tor_dir_src,
            output_dir=output_dir / "disk",
        )
    except AcquisitionError as exc:
        return {"status": "error", "message": str(exc)}


def _print_category(name: str, result: dict) -> None:
    """registry_acquire.acquire_all() already prints its own per-hive lines as it goes
    (see modules/module_a_registry/acquire.py); memory/disk's helpers here only return
    a result dict, so without this the console shows registry's progress and nothing
    else -- silent, but not actually skipped: a real failure (e.g. no firefox.exe
    running, no --tor-browser-dir given) with zero console feedback looks identical to
    the step never having been attempted at all."""
    if result.get("status") == "error":
        print(f"[!] {name}: {result.get('message')}", file=sys.stderr)
        return
    for key, entry in result.items():
        if not isinstance(entry, dict):
            continue
        status = entry.get("status", "?")
        detail = entry.get("path") or entry.get("message") or ""
        print(f"[*] {name}.{key}: {status}{' — ' + detail if detail else ''}")


def acquire(
    output_dir: Path,
    include_registry: bool = True,
    include_memory: bool = True,
    include_disk: bool = True,
    ntuser_user: str | None = None,
    winpmem_path: Path | None = None,
    tor_browser_dir: Path | None = None,
    disk_profile_src: Path | None = None,
    tor_dir_src: Path | None = None,
) -> dict:
    if sys.platform != "win32":
        raise AcquisitionError("Acquisition only runs on Windows.")
    if not is_admin():
        raise AcquisitionError(
            "Not running elevated. Re-run as Administrator -- registry and memory "
            "acquisition both need it."
        )

    output_dir.mkdir(parents=True, exist_ok=True)
    manifest: dict = {
        "acquired_at": datetime.now(timezone.utc).isoformat(),
        "registry": {},
        "memory": {},
        "disk": {},
    }

    if include_registry:
        manifest["registry"] = _acquire_registry(output_dir, ntuser_user)
        # registry_acquire.acquire_all() already prints its own per-hive lines
    else:
        print("[*] registry: skipped (--skip-registry)")

    if include_memory:
        manifest["memory"] = _acquire_memory(output_dir, winpmem_path)
        _print_category("memory", manifest["memory"])
    else:
        print("[*] memory: skipped (--skip-memory)")

    if include_disk:
        manifest["disk"] = _acquire_disk(output_dir, tor_browser_dir, disk_profile_src, tor_dir_src)
        _print_category("disk", manifest["disk"])
    else:
        print("[*] disk: skipped (--skip-disk)")

    _make_paths_portable(manifest, output_dir)
    manifest_path = output_dir / "acquire_manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2))
    manifest["manifest_path"] = str(manifest_path)
    return manifest


_EVIDENCE_PATH_KEYS = ("path", "custody_log_path")


def _make_paths_portable(node: object, output_dir: Path) -> None:
    """Rewrite evidence paths in place as relative to output_dir with "/" separators.

    The folder gets copied off the target to the examiner's machine (usually a
    different OS and location), so a path relative to the acquire-time CWD, or absolute
    on the target, is meaningless there. Only evidence *outputs* are rewritten
    (path/custody_log_path); source locations on the target like winpmem_path or
    other_installations_found are provenance and stay as recorded.
    """
    if isinstance(node, dict):
        for key, value in node.items():
            if key in _EVIDENCE_PATH_KEYS and isinstance(value, str):
                node[key] = _relative_to_output(value, output_dir)
            else:
                _make_paths_portable(value, output_dir)
    elif isinstance(node, list):
        for item in node:
            _make_paths_portable(item, output_dir)


def _relative_to_output(value: str, output_dir: Path) -> str:
    try:
        return Path(value).resolve().relative_to(output_dir.resolve()).as_posix()
    except ValueError:
        return value


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Run every TRANCE acquisition step into one evidence folder."
    )
    parser.add_argument(
        "--output-dir", type=Path, default=Path("evidence"), help="Default: %(default)s"
    )
    parser.add_argument("--skip-registry", action="store_true")
    parser.add_argument("--skip-memory", action="store_true")
    parser.add_argument("--skip-disk", action="store_true")
    parser.add_argument(
        "--ntuser-user", help="Named user's NTUSER.DAT via VSS instead of the live HKCU export"
    )
    parser.add_argument(
        "--winpmem-path",
        type=Path,
        help="Full physical-memory image via this examiner-supplied WinPMEM binary, "
        "always attempted alongside the live dump (not just when the live dump fails). "
        "Omit to auto-discover instead: scans the home directory/Desktop/Downloads/"
        "Documents, then every drive, for one",
    )
    parser.add_argument(
        "--tor-browser-dir",
        type=Path,
        help="Root of a portable Tor Browser install. Omit to auto-discover instead: "
        "scans the home directory/Desktop/Downloads/Documents, then every drive, for "
        "one",
    )
    parser.add_argument("--disk-profile-src", type=Path, help="Explicit profile source dir")
    parser.add_argument("--tor-dir-src", type=Path, help="Explicit Tor daemon data dir source")
    args = parser.parse_args(argv)

    try:
        manifest = acquire(
            args.output_dir,
            include_registry=not args.skip_registry,
            include_memory=not args.skip_memory,
            include_disk=not args.skip_disk,
            ntuser_user=args.ntuser_user,
            winpmem_path=args.winpmem_path,
            tor_browser_dir=args.tor_browser_dir,
            disk_profile_src=args.disk_profile_src,
            tor_dir_src=args.tor_dir_src,
        )
    except AcquisitionError as exc:
        print(f"[!] {exc}", file=sys.stderr)
        return 1

    print(f"\n[*] Evidence folder: {args.output_dir}")
    print(f"[*] Manifest:        {manifest['manifest_path']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
