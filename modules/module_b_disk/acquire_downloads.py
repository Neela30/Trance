"""Live Zone.Identifier scan on the Windows target (acquire side of the downloads
correlation).

analyze_downloads.scan_volume() finds internet-origin files on a read-only ntfs-3g
mount, which needs a separately imaged and mounted volume that trance-acquire.exe
never produces. On the live target the same evidence is directly readable: Windows
exposes the mark-of-the-web as the `<file>:Zone.Identifier` stream and NTFS creation
times through os.stat. This walks every drive (the same skip-list as Tor Browser
auto-discovery minus $Recycle.Bin, so no assumption about a Downloads folder and
deleted downloads are still found) and writes a report in
exactly scan_volume()'s shape, so module_b_disk.correlate_downloads() and the report
presenter consume it unchanged.

Only metadata and a SHA-256 of each marked file are recorded -- the files themselves
are not copied (they can be large, and are the suspect's content, not ours to move).
"""

from __future__ import annotations

import datetime as dt
import os
import time
from collections.abc import Callable
from pathlib import Path

from core import fs_scan
from core.hashing import hash_file
from modules.module_b_disk.analyze_downloads import (
    ZONE_STREAM,
    parse_zone_identifier,
    recycle_bin_info,
)

SCAN_METHOD = "live_windows"
# Deeper than Tor Browser discovery's default: a download can sit anywhere under
# C:\Users\<name>\AppData\..., which is already 4-5 levels down.
SCAN_MAX_DEPTH = 16
# Tor Browser discovery skips $Recycle.Bin; this scan must not: a download the suspect
# deleted sits there with its Zone.Identifier stream intact.
SKIP_DIR_NAMES = frozenset(fs_scan.SKIP_DIR_NAMES - {"$Recycle.Bin"})


def _read_stream_windows(path: str, stream: str) -> bytes | None:
    try:
        with open(f"{path}:{stream}", "rb") as fh:
            return fh.read(65536)
    except OSError:
        return None


def _utc(epoch: float | None) -> str | None:
    if epoch is None:
        return None
    return dt.datetime.fromtimestamp(epoch, dt.timezone.utc).isoformat()


def file_times(st: os.stat_result) -> dict:
    """NTFS times as Windows reports them. st_birthtime is the creation time on
    Python 3.12+; on older Pythons st_ctime is the creation time on Windows."""
    created = getattr(st, "st_birthtime", None)
    if created is None and os.name == "nt":
        created = st.st_ctime
    return {
        "source": "win32_stat",
        "created_utc": _utc(created),
        "modified_utc": _utc(st.st_mtime),
        "mft_changed_utc": None,
        "accessed_utc": _utc(st.st_atime),
    }


def scan_live(
    roots: list[Path],
    exclude: list[Path] | None = None,
    read_stream: Callable[[str, str], bytes | None] = _read_stream_windows,
    max_depth: int = SCAN_MAX_DEPTH,
) -> dict:
    """Walk each root and record every regular file carrying a Zone.Identifier
    stream. `exclude` keeps the acquisition's own output folder out of the scan."""
    excluded = [p.resolve() for p in (exclude or [])]
    started = time.monotonic()
    files_walked = 0
    unreadable = 0
    hits = []
    for root in roots:
        for current, dirnames, filenames in fs_scan.walk_pruned(root, max_depth, SKIP_DIR_NAMES):
            if any(current == e or current.is_relative_to(e) for e in excluded):
                dirnames[:] = []
                continue
            for name in filenames:
                path = current / name
                if path.is_symlink():
                    continue
                files_walked += 1
                stream = read_stream(str(path), ZONE_STREAM)
                if stream is None:
                    continue
                try:
                    st = path.stat()
                    digest = hash_file(path)
                except OSError:
                    unreadable += 1
                    continue
                hit = {
                    "path": str(path),
                    "size": st.st_size,
                    "sha256": digest,
                    "zone_identifier": parse_zone_identifier(stream),
                    "timestamps": file_times(st),
                }
                recycled = recycle_bin_info(path)
                if recycled:
                    hit["recycle_bin"] = recycled
                hits.append(hit)
    hits.sort(key=lambda h: h["timestamps"]["created_utc"] or h["timestamps"]["modified_utc"] or "")
    return {
        "scan_method": SCAN_METHOD,
        "volume_root": ", ".join(str(r) for r in roots),
        "files_walked": files_walked,
        "unreadable_marked_files": unreadable,
        "scan_seconds": round(time.monotonic() - started, 1),
        # Windows reads streams and NTFS creation times natively -- the ntfs-3g caveat
        # the report attaches to xattr_support False/None doesn't apply to a live scan.
        "xattr_support": True,
        "internet_origin_files": hits,
    }
