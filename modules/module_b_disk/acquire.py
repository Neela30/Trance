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
import datetime as dt
import json
import os
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


METADATA_FILENAME = "filesystem_metadata.json"
DOWNLOADS_SCAN_FILENAME = "zone_identifier_scan.json"


def _iso_utc(epoch: float | None) -> str | None:
    if epoch is None:
        return None
    return dt.datetime.fromtimestamp(epoch, dt.timezone.utc).isoformat()


def source_file_metadata(path: Path) -> dict:
    """The source file's own timestamps, read before copying. A copy gets new
    timestamps on the examiner side (and again on every later copy), so these are
    the only record of when tor/Firefox actually wrote the file -- the daemon
    window in module_b_disk.daemon_window() is built from them. stat() works even
    on a file the running tor.exe holds locked."""
    st = path.stat()
    created = getattr(st, "st_birthtime", None)
    if created is None and os.name == "nt":
        created = st.st_ctime  # creation time on Windows before Python 3.12
    return {
        "inode": str(st.st_ino),
        "size": st.st_size,
        "created_utc": _iso_utc(created),
        "modified_utc": _iso_utc(st.st_mtime),
        "accessed_utc": _iso_utc(st.st_atime),
    }


def _copy_one(source: Path, target: Path, relative: str, result: dict) -> None:
    """Copy one file, recording its source metadata first. A file that can't be read
    (tor.exe keeps `lock` locked while running) is recorded under "failed" with its
    metadata kept, rather than aborting every file after it."""
    result["metadata"][relative] = source_file_metadata(source)
    try:
        shutil.copy2(source, target)
    except OSError as exc:
        result["failed"][relative] = f"{type(exc).__name__}: {exc}"
        result["metadata"][relative]["copied"] = False
        return
    result["metadata"][relative]["copied"] = True
    result["copied"].append(relative)


def _new_copy_result() -> dict:
    return {"copied": [], "missing": [], "failed": {}, "metadata": {}}


def _copy_known_files(src: Path, dest: Path, filenames: tuple[str, ...]) -> dict:
    """Best-effort copy: each filename is attempted independently, missing or
    unreadable ones are recorded and skipped rather than failing the whole step."""
    dest.mkdir(parents=True, exist_ok=True)
    result = _new_copy_result()
    for name in filenames:
        source = src / name
        if not source.is_file():
            result["missing"].append(name)
            continue
        _copy_one(source, dest / name, name, result)
    return result


def _copy_glob(src_dir: Path, dest_dir: Path, pattern: str, result: dict) -> list[str]:
    copied = []
    if not src_dir.is_dir():
        return copied
    dest_dir.mkdir(parents=True, exist_ok=True)
    for source in sorted(src_dir.glob(pattern)):
        relative = f"{src_dir.name}/{source.name}"
        _copy_one(source, dest_dir / source.name, relative, result)
        if relative in result["copied"]:
            result["copied"].remove(relative)
            copied.append(source.name)
    return copied


def tor_daemon_running(tor_dir_src: Path) -> bool:
    """Whether a tor.exe from this install is running right now. If it is, the
    daemon's session hasn't ended: the analysis side extends the session window to
    the capture time instead of stopping at tor's last file write."""
    try:
        import psutil
    except ImportError:
        return False
    parents = tor_dir_src.resolve().parents
    # .../Browser/TorBrowser/Data/Tor -> .../Browser, which also holds TorBrowser/Tor/tor.exe
    install_root = parents[2] if len(parents) > 2 else tor_dir_src.resolve()
    for proc in psutil.process_iter(["name", "exe"]):
        name = (proc.info.get("name") or "").lower()
        if name not in ("tor.exe", "tor"):
            continue
        exe = proc.info.get("exe")
        if not exe:
            return True  # can't read its path; a running tor is still a running tor
        try:
            if Path(exe).resolve().is_relative_to(install_root):
                return True
        except OSError:
            continue
    return False


def write_metadata(dest: Path, src: Path, copy_result: dict, **extra: object) -> Path:
    """Persist source timestamps next to the copy, in the format
    analyze_tor_datadir._load_filesystem_metadata() reads. Written before
    hashes.sha256 so the manifest covers it."""
    path = dest / METADATA_FILENAME
    payload = {
        "captured_at_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
        "source_dir": str(src),
        **extra,
        "files": copy_result.pop("metadata"),
    }
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return path


def copy_profile(src: Path, dest: Path) -> dict:
    result = _copy_known_files(src, dest, PROFILE_FILENAMES)
    result["bookmark_backups_copied"] = _copy_glob(
        src / "bookmarkbackups", dest / "bookmarkbackups", "*.jsonlz4", result
    )
    return result


def copy_tor_datadir(src: Path, dest: Path) -> dict:
    result = _copy_known_files(src, dest, TOR_DATADIR_FILENAMES)
    result["onion_auth_copied"] = _copy_glob(
        src / "onion-auth", dest / "onion-auth", "*.auth_private", result
    )
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
    write_metadata(dest, src, copy_result)
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
    return {"path": str(dest), "source_dir": str(src), **copy_result}


def acquire_tor_datadir(src: Path, output_dir: Path, custody: CustodyLog) -> dict:
    dest = output_dir / "tor_dir"
    running = tor_daemon_running(src)
    copy_result = copy_tor_datadir(src, dest)
    write_metadata(dest, src, copy_result, tor_running_at_capture=running)
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
    return {
        "path": str(dest),
        "source_dir": str(src),
        "tor_running_at_capture": running,
        **copy_result,
    }


def acquire_downloads(
    output_dir: Path, custody: CustodyLog, scan_roots: list[Path] | None = None
) -> dict:
    """Live Zone.Identifier scan for the downloads-vs-Tor-session correlation. Only
    meaningful on Windows (NTFS streams); skipped elsewhere unless roots are given."""
    from modules.module_b_disk.acquire_downloads import scan_live

    if scan_roots is None:
        if sys.platform != "win32":
            return {"status": "skipped", "message": "Zone.Identifier scan needs a Windows target"}
        scan_roots = fs_scan.drive_search_roots()
    dest = output_dir / "downloads"
    dest.mkdir(parents=True, exist_ok=True)
    print(f"[*] downloads: scanning {', '.join(map(str, scan_roots))} for Zone.Identifier ...")
    report = scan_live(scan_roots, exclude=[output_dir.parent])
    report_path = dest / DOWNLOADS_SCAN_FILENAME
    report_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    manifest = write_hash_manifest(dest)
    for name, digest in _manifest_entries(manifest):
        custody.record(
            CustodyEntry(
                artifact_path=str(dest / name),
                sha256=digest,
                action="acquire",
                notes="live Zone.Identifier scan; marked files hashed in place, not copied",
            )
        )
    return {
        "status": "ok",
        "path": str(report_path),
        "files_walked": report["files_walked"],
        "internet_origin_files": len(report["internet_origin_files"]),
    }


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
    downloads_scan_roots: list[Path] | None = None,
) -> dict:
    """Best-effort: profile, Tor data dir and downloads scan are attempted
    independently, same isolation philosophy as module_a_registry.acquire.acquire_all().
    Explicit profile_src/tor_dir_src override tor_browser_dir discovery, which in turn
    overrides auto-discovery (find_tor_browser_installations()) -- so this still
    works with no path given at all, not just as a fallback.

    Finding no install is a per-step error on profile/tor_dir, not a reason to stop:
    the downloads scan doesn't depend on the install, and a deleted install is exactly
    when the files it downloaded are the evidence left."""
    other_installations: list[str] = []
    discovery_error: str | None = None
    if profile_src is None or tor_dir_src is None:
        try:
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
        except AcquisitionError as exc:
            discovery_error = str(exc)
            print(f"[!] {discovery_error}", file=sys.stderr)

    output_dir.mkdir(parents=True, exist_ok=True)
    custody = CustodyLog(output_dir / f"disk_acquire_{_timestamp()}.custody.json")
    results: dict[str, dict] = {}
    if other_installations:
        results["other_installations_found"] = other_installations
        print(
            f"[*] found {len(other_installations)} other Tor Browser install(s), "
            f"not acquired (used the most recently active one): {other_installations}"
        )

    if profile_src is None:
        results["profile"] = {"status": "error", "message": discovery_error}
    else:
        try:
            results["profile"] = {
                "status": "ok",
                **acquire_profile(profile_src, output_dir, custody),
            }
            print(f"[*] profile: {results['profile']['path']}")
        except (AcquisitionError, OSError) as exc:
            results["profile"] = {"status": "error", "message": str(exc)}
            print(f"[!] profile failed: {exc}", file=sys.stderr)

    if tor_dir_src is None:
        results["tor_dir"] = {"status": "error", "message": discovery_error}
    else:
        try:
            results["tor_dir"] = {
                "status": "ok",
                **acquire_tor_datadir(tor_dir_src, output_dir, custody),
            }
            print(f"[*] tor_dir: {results['tor_dir']['path']}")
        except (AcquisitionError, OSError) as exc:
            results["tor_dir"] = {"status": "error", "message": str(exc)}
            print(f"[!] tor_dir failed: {exc}", file=sys.stderr)

    try:
        results["downloads"] = acquire_downloads(output_dir, custody, downloads_scan_roots)
    except OSError as exc:
        results["downloads"] = {"status": "error", "message": str(exc)}
        print(f"[!] downloads scan failed: {exc}", file=sys.stderr)

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
