"""Disk evidence acquisition for Module B (Windows target, no elevation required).

Copies the Tor Browser profile and Tor daemon data directory that
modules/module_b_disk/recover_evidence.py and analyze_tor_datadir.py analyze,
mirroring module_a_registry's acquire-then-analyze split: acquisition happens
on the live target, analysis runs anywhere, offline, against the copies.

Unlike the registry hives, these files are not exclusively locked by the OS,
so a plain file copy (no `reg save`/VSS) is enough -- but Tor Browser should
be closed first if possible: copying a sqlite database that's still being
written mid-transaction can produce an inconsistent snapshot. This does not
use a Volume Shadow Copy the way module_a_registry.acquire does for
Amcache.hve; that's a known limitation, not an oversight -- see acquire_all's
docstring below.

Writes a `hashes.sha256` manifest next to each copy, in the same format
`sha256sum` itself produces (`<64-hex><space><space-or-asterisk><relative
path>`) -- this is exactly what modules/module_b_disk/evidence.py's
verify_hashes() already parses, so a folder this module produces is usable
by main.py's --disk-profile/--tor-dir immediately, no separate manifest step.

Tor Browser is portable (no fixed install path). --tor-browser-dir still
works if you already know where it is (faster, no scan); if none of
--tor-browser-dir/--disk-profile-src/--tor-dir-src are given, acquire_all()
instead walks the filesystem looking for Tor Browser's own install
signature (Browser/TorBrowser/Data/Tor/torrc) -- see
find_tor_browser_installations().
"""

from __future__ import annotations

import argparse
import shutil
import sys
import time
from pathlib import Path

from core import fs_scan
from core.custody_log import CustodyEntry, CustodyLog
from core.exceptions import AcquisitionError
from core.hashing import hash_file

# The one file that's unique and constant across every real Tor Browser install --
# present the moment the daemon has ever started, portable installs included.
_TOR_MARKER = Path("Browser") / "TorBrowser" / "Data" / "Tor" / "torrc"
_SCAN_MAX_DEPTH = fs_scan.DEFAULT_MAX_DEPTH

PROFILE_FILENAMES: tuple[str, ...] = (
    "places.sqlite",
    "places.sqlite-wal",
    "places.sqlite-shm",
    "cookies.sqlite",
    "cookies.sqlite-wal",
    "cookies.sqlite-shm",
    "favicons.sqlite",
    "favicons.sqlite-wal",
    "favicons.sqlite-shm",
)
TOR_DATADIR_FILENAMES: tuple[str, ...] = (
    "state",
    "cached-microdesc-consensus",
    "cached-microdescs",
    "cached-microdescs.new",
    "torrc",
    "lock",
)


def _scan_for_marker(root: Path, max_depth: int = _SCAN_MAX_DEPTH) -> list[Path]:
    """Walk root looking for Browser/TorBrowser/Data/Tor/torrc; returns each match's
    Tor Browser root directory (the folder containing Browser/), never descending into
    a found install itself."""
    found = []
    for current, dirnames, _filenames in fs_scan.walk_pruned(root, max_depth):
        if (current / _TOR_MARKER).is_file():
            found.append(current)
            dirnames[:] = []  # nothing relevant further down a found install
    return found


def find_tor_browser_installations(search_roots: list[Path] | None = None) -> list[Path]:
    """Auto-discovery for when the examiner doesn't already know where Tor Browser
    lives on this target -- see core.fs_scan.staged_scan for the fast-locations-first,
    full-drive-fallback search order."""
    return fs_scan.staged_scan(_scan_for_marker, search_roots)


def discover_tor_browser_paths(tor_browser_dir: Path) -> tuple[Path, Path]:
    """Locate the Firefox profile dir and Tor daemon data dir under a portable
    Tor Browser install root. Raises AcquisitionError if either isn't found,
    or is ambiguous (more than one candidate profile directory)."""
    data_browser = tor_browser_dir / "Browser" / "TorBrowser" / "Data" / "Browser"
    tor_dir = tor_browser_dir / "Browser" / "TorBrowser" / "Data" / "Tor"
    candidates = sorted(data_browser.glob("*.default")) if data_browser.is_dir() else []
    if not candidates:
        raise AcquisitionError(
            f"No Tor Browser profile found under {data_browser} (expected a *.default directory)"
        )
    if len(candidates) > 1:
        raise AcquisitionError(
            f"Multiple candidate profiles under {data_browser}, pass --disk-profile-src "
            f"explicitly: {[str(c) for c in candidates]}"
        )
    if not tor_dir.is_dir():
        raise AcquisitionError(f"Tor daemon data directory not found: {tor_dir}")
    return candidates[0], tor_dir


def _copy_known_files(src: Path, dest: Path, filenames: tuple[str, ...]) -> dict:
    """Best-effort copy: each filename is attempted independently, missing ones
    are recorded and skipped rather than failing the whole step."""
    dest.mkdir(parents=True, exist_ok=True)
    copied: list[str] = []
    missing: list[str] = []
    for name in filenames:
        source = src / name
        if not source.is_file():
            missing.append(name)
            continue
        shutil.copyfile(source, dest / name)
        copied.append(name)
    return {"copied": copied, "missing": missing}


def copy_profile(src: Path, dest: Path) -> dict:
    result = _copy_known_files(src, dest, PROFILE_FILENAMES)
    backups_src = src / "bookmarkbackups"
    backups_dest = dest / "bookmarkbackups"
    backups_copied = []
    if backups_src.is_dir():
        backups_dest.mkdir(parents=True, exist_ok=True)
        for backup in sorted(backups_src.glob("*.jsonlz4")):
            shutil.copyfile(backup, backups_dest / backup.name)
            backups_copied.append(backup.name)
    result["bookmark_backups_copied"] = backups_copied
    return result


def copy_tor_datadir(src: Path, dest: Path) -> dict:
    result = _copy_known_files(src, dest, TOR_DATADIR_FILENAMES)
    auth_src = src / "onion-auth"
    auth_dest = dest / "onion-auth"
    auth_copied = []
    if auth_src.is_dir():
        auth_dest.mkdir(parents=True, exist_ok=True)
        for credential in sorted(auth_src.glob("*.auth_private")):
            shutil.copyfile(credential, auth_dest / credential.name)
            auth_copied.append(credential.name)
    result["onion_auth_copied"] = auth_copied
    return result


def write_hash_manifest(root: Path) -> Path:
    """Write hashes.sha256 for every regular file already copied under root, in
    sha256sum's own output format -- exactly what evidence.verify_hashes() parses."""
    manifest_path = root / "hashes.sha256"
    lines = []
    for path in sorted(root.rglob("*")):
        if not path.is_file() or path == manifest_path:
            continue
        digest = hash_file(path)
        lines.append(f"{digest}  {path.relative_to(root).as_posix()}")
    manifest_path.write_text("\n".join(lines) + ("\n" if lines else ""))
    return manifest_path


def _timestamp() -> str:
    return time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())


def acquire_profile(src: Path, output_dir: Path, custody: CustodyLog) -> dict:
    dest = output_dir / "profile"
    copy_result = copy_profile(src, dest)
    manifest = write_hash_manifest(dest)
    for name, digest in _manifest_entries(manifest):
        custody.record(
            CustodyEntry(
                artifact_path=str(dest / name),
                sha256=digest,
                action="acquire",
                notes="Tor Browser profile file, plain copy (not VSS)",
            )
        )
    return {"path": str(dest), **copy_result}


def acquire_tor_datadir(src: Path, output_dir: Path, custody: CustodyLog) -> dict:
    dest = output_dir / "tor_dir"
    copy_result = copy_tor_datadir(src, dest)
    manifest = write_hash_manifest(dest)
    for name, digest in _manifest_entries(manifest):
        custody.record(
            CustodyEntry(
                artifact_path=str(dest / name),
                sha256=digest,
                action="acquire",
                notes="Tor daemon data directory file, plain copy (not VSS)",
            )
        )
    return {"path": str(dest), **copy_result}


def _manifest_entries(manifest_path: Path) -> list[tuple[str, str]]:
    entries = []
    for line in manifest_path.read_text().splitlines():
        if not line.strip():
            continue
        digest, name = line.split("  ", 1)
        entries.append((name, digest))
    return entries


def _most_recently_active(installations: list[Path]) -> Path:
    """When auto-discovery finds more than one install, the one whose torrc was
    written to most recently is the best guess at "the one actually in use" --
    torrc's mtime tracks whenever that daemon last started."""
    return max(installations, key=lambda p: (p / _TOR_MARKER).stat().st_mtime)


def acquire_all(
    tor_browser_dir: Path | None = None,
    profile_src: Path | None = None,
    tor_dir_src: Path | None = None,
    output_dir: Path = Path("captures/disk"),
) -> dict:
    """Best-effort: profile and Tor data dir are attempted independently, same
    isolation philosophy as module_a_registry.acquire.acquire_all(). Explicit
    profile_src/tor_dir_src override tor_browser_dir discovery, which in turn
    overrides auto-discovery (find_tor_browser_installations()) -- so this still
    works with no path given at all, not just as a fallback."""
    other_installations: list[str] = []
    if profile_src is None or tor_dir_src is None:
        if tor_browser_dir is not None:
            chosen = tor_browser_dir
        else:
            installations = find_tor_browser_installations()
            if not installations:
                raise AcquisitionError(
                    "No Tor Browser installation found (searched the home directory, "
                    "Desktop, Downloads, Documents, then every drive). Pass "
                    "--tor-browser-dir, or both --disk-profile-src and --tor-dir-src, "
                    "explicitly if it's somewhere this scan wouldn't find it."
                )
            chosen = _most_recently_active(installations)
            other_installations = [str(p) for p in installations if p != chosen]
        discovered_profile, discovered_tor_dir = discover_tor_browser_paths(chosen)
        profile_src = profile_src or discovered_profile
        tor_dir_src = tor_dir_src or discovered_tor_dir

    output_dir.mkdir(parents=True, exist_ok=True)
    custody = CustodyLog(output_dir / f"disk_acquire_{_timestamp()}.custody.json")
    results: dict[str, dict] = {}
    if other_installations:
        results["other_installations_found"] = other_installations
        print(
            f"[*] found {len(other_installations)} other Tor Browser install(s), "
            f"not acquired (used the most recently active one): {other_installations}"
        )

    try:
        results["profile"] = {
            "status": "ok",
            **acquire_profile(profile_src, output_dir, custody),
        }
        print(f"[*] profile: {results['profile']['path']}")
    except (AcquisitionError, OSError) as exc:
        results["profile"] = {"status": "error", "message": str(exc)}
        print(f"[!] profile failed: {exc}", file=sys.stderr)

    try:
        results["tor_dir"] = {
            "status": "ok",
            **acquire_tor_datadir(tor_dir_src, output_dir, custody),
        }
        print(f"[*] tor_dir: {results['tor_dir']['path']}")
    except (AcquisitionError, OSError) as exc:
        results["tor_dir"] = {"status": "error", "message": str(exc)}
        print(f"[!] tor_dir failed: {exc}", file=sys.stderr)

    custody.save()
    results["custody_log_path"] = str(custody.log_path)
    return results


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Copy a Tor Browser profile and Tor daemon data directory from a live "
        "Windows target for Module B. Close Tor Browser first if possible -- this copies "
        "live files, not a Volume Shadow Copy."
    )
    parser.add_argument(
        "--output-dir", type=Path, default=Path("captures/disk"), help="Default: %(default)s"
    )
    parser.add_argument(
        "--tor-browser-dir",
        type=Path,
        help="Root of a portable Tor Browser install; profile and Tor data dir are "
        "discovered under it. Omit entirely to auto-discover: scans the home "
        "directory/Desktop/Downloads/Documents, then every drive, for a Tor Browser "
        "install; picks the most recently active one if it finds several",
    )
    parser.add_argument(
        "--disk-profile-src", type=Path, help="Explicit profile source dir (overrides discovery)"
    )
    parser.add_argument(
        "--tor-dir-src", type=Path, help="Explicit Tor data dir source (overrides discovery)"
    )
    args = parser.parse_args()

    try:
        results = acquire_all(
            tor_browser_dir=args.tor_browser_dir,
            profile_src=args.disk_profile_src,
            tor_dir_src=args.tor_dir_src,
            output_dir=args.output_dir,
        )
    except AcquisitionError as exc:
        print(f"[!] {exc}", file=sys.stderr)
        sys.exit(1)

    failed = [k for k, v in results.items() if isinstance(v, dict) and v.get("status") == "error"]
    print(f"\n[*] Custody log: {results['custody_log_path']}")
    if failed:
        print(f"[!] {len(failed)} step(s) failed: {', '.join(failed)}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
