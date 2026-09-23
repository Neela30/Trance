"""TRANCE combined acquire entry point: run every acquisition step into one
evidence folder on a live Windows target (elevated).

    python acquire_all.py --output-dir evidence \\
        --tor-browser-dir "C:\\Users\\investigator\\Desktop\\Tor Browser"

Writes <output-dir>/{registry,memory,disk}/... and <output-dir>/
acquire_manifest.json -- the contract analyze_evidence.py reads to resolve
each artifact's path without the examiner having to type them all by hand.

Registry (SYSTEM/NTUSER/Amcache) and the live memory dump need an elevated
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
    result: dict = {}
    try:
        dump_path = memory_dumper.acquire(output_dir / "memory")
        result["live_dump"] = {"status": "ok", "path": str(dump_path), "source_type": "process"}
    except AcquisitionError as exc:
        result["live_dump"] = {"status": "error", "message": str(exc)}

    if winpmem_path is not None:
        try:
            image_path = winpmem_acquire.acquire(winpmem_path, output_dir / "memory")
            result["full_image"] = {
                "status": "ok",
                "path": str(image_path),
                "source_type": "full-memory",
            }
        except AcquisitionError as exc:
            result["full_image"] = {"status": "error", "message": str(exc)}
    else:
        result["full_image"] = {"status": "skipped", "message": "no --winpmem-path supplied"}
    return result


def _acquire_disk(
    output_dir: Path,
    tor_browser_dir: Path | None,
    disk_profile_src: Path | None,
    tor_dir_src: Path | None,
) -> dict:
    if tor_browser_dir is None and disk_profile_src is None and tor_dir_src is None:
        return {
            "profile": {"status": "skipped", "message": "no --tor-browser-dir/--disk-profile-src"},
            "tor_dir": {"status": "skipped", "message": "no --tor-browser-dir/--tor-dir-src"},
        }
    try:
        return disk_acquire.acquire_all(
            tor_browser_dir=tor_browser_dir,
            profile_src=disk_profile_src,
            tor_dir_src=tor_dir_src,
            output_dir=output_dir / "disk",
        )
    except AcquisitionError as exc:
        return {"status": "error", "message": str(exc)}


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
    if include_memory:
        manifest["memory"] = _acquire_memory(output_dir, winpmem_path)
    if include_disk:
        manifest["disk"] = _acquire_disk(output_dir, tor_browser_dir, disk_profile_src, tor_dir_src)

    manifest_path = output_dir / "acquire_manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2))
    manifest["manifest_path"] = str(manifest_path)
    return manifest


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
        help="Also (or instead of the live dump) acquire a full physical-memory image via "
        "this examiner-supplied WinPMEM binary",
    )
    parser.add_argument(
        "--tor-browser-dir", type=Path, help="Root of a portable Tor Browser install"
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
