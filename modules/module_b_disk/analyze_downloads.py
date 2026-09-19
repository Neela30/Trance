"""Find internet-origin files anywhere on a mounted Windows volume.

Windows' Attachment Execution Service tags every file a browser saves from
the network with a `Zone.Identifier` alternate data stream (the
"mark-of-the-web"). Locally created or ISO/USB-copied files never carry it,
so walking the whole volume and keeping only files with that stream finds
downloads regardless of where the user chose to save them -- no assumption
about a Downloads folder.

Tor Browser deliberately omits the HostUrl/ReferrerUrl fields other browsers
write into the stream, so the source URL is not recoverable from here. What
the stream does establish is network origin; correlation against the Tor
daemon's activity window (see module_b_disk.__init__) supplies the timing.

Requires the volume to be mounted through ntfs-3g, which exposes the stream
as the `user.Zone.Identifier` xattr and the four NTFS timestamps as
`system.ntfs_times` (creation, modification, MFT-change, access; little-endian
FILETIME each). Without those xattrs the scan finds nothing, and says so.

Usage:
    python analyze_downloads.py <mounted_volume_root> [--out report.json]
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import struct
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from core.hashing import hash_file

ZONE_STREAM_XATTR = "user.Zone.Identifier"
NTFS_TIMES_XATTR = "system.ntfs_times"
_FILETIME_EPOCH = dt.datetime(1601, 1, 1, tzinfo=dt.timezone.utc)


def _read_xattr(path: str, name: str) -> bytes | None:
    try:
        return os.getxattr(path, name, follow_symlinks=False)
    except OSError:
        return None


def _filetime_to_utc(value: int) -> str | None:
    if value == 0:
        return None
    return (_FILETIME_EPOCH + dt.timedelta(microseconds=value / 10)).isoformat()


def parse_zone_identifier(raw: bytes) -> dict:
    fields: dict[str, str] = {}
    for line in raw.decode("utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line or line.startswith("[") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        fields[key.strip()] = value.strip()
    zone = fields.get("ZoneId")
    return {
        "zone_id": int(zone) if zone and zone.isdigit() else None,
        "host_url": fields.get("HostUrl"),
        "referrer_url": fields.get("ReferrerUrl"),
        "raw": raw.decode("utf-8", errors="replace"),
    }


def ntfs_timestamps(path: str) -> dict:
    raw = _read_xattr(path, NTFS_TIMES_XATTR)
    if raw and len(raw) >= 32:
        created, modified, mft_changed, accessed = struct.unpack("<4Q", raw[:32])
        return {
            "source": "ntfs",
            "created_utc": _filetime_to_utc(created),
            "modified_utc": _filetime_to_utc(modified),
            "mft_changed_utc": _filetime_to_utc(mft_changed),
            "accessed_utc": _filetime_to_utc(accessed),
        }
    st = os.lstat(path)
    return {
        "source": "stat",
        "created_utc": None,
        "modified_utc": dt.datetime.fromtimestamp(st.st_mtime, dt.timezone.utc).isoformat(),
        "mft_changed_utc": dt.datetime.fromtimestamp(st.st_ctime, dt.timezone.utc).isoformat(),
        "accessed_utc": dt.datetime.fromtimestamp(st.st_atime, dt.timezone.utc).isoformat(),
    }


def scan_volume(root: Path) -> dict:
    """Walk `root` and record every regular file carrying a Zone.Identifier stream."""
    root = root.resolve(strict=True)
    if not root.is_dir():
        raise ValueError(f"not a directory: {root}")
    started = time.monotonic()
    files_walked = 0
    unreadable = 0
    hits = []
    for dirpath, dirnames, filenames in os.walk(root, onerror=lambda _: None):
        dirnames[:] = [d for d in dirnames if not os.path.islink(os.path.join(dirpath, d))]
        for name in filenames:
            path = os.path.join(dirpath, name)
            if os.path.islink(path):
                continue
            files_walked += 1
            stream = _read_xattr(path, ZONE_STREAM_XATTR)
            if stream is None:
                continue
            try:
                digest = hash_file(Path(path))
                size = os.lstat(path).st_size
            except OSError:
                unreadable += 1
                continue
            hits.append(
                {
                    "path": os.path.relpath(path, root),
                    "size": size,
                    "sha256": digest,
                    "zone_identifier": parse_zone_identifier(stream),
                    "timestamps": ntfs_timestamps(path),
                }
            )
    hits.sort(key=lambda h: h["timestamps"]["created_utc"] or h["timestamps"]["modified_utc"] or "")
    return {
        "volume_root": str(root),
        "files_walked": files_walked,
        "unreadable_marked_files": unreadable,
        "scan_seconds": round(time.monotonic() - started, 1),
        "xattr_support": any(h["timestamps"]["source"] == "ntfs" for h in hits) if hits else None,
        "internet_origin_files": hits,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root", type=Path, help="Root of the read-only mounted NTFS volume")
    parser.add_argument("--out", type=Path, help="Write the JSON report here")
    args = parser.parse_args(argv)
    try:
        report = scan_volume(args.root)
    except (OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        with args.out.open("x", encoding="utf-8") as stream:
            json.dump(report, stream, indent=2)
    print("=== TRANCE Module B — Internet-origin files ===")
    print(f"walked {report['files_walked']} files in {report['scan_seconds']}s")
    print(f"files with Zone.Identifier: {len(report['internet_origin_files'])}")
    for hit in report["internet_origin_files"]:
        ts = hit["timestamps"]["created_utc"] or hit["timestamps"]["modified_utc"]
        zone = hit["zone_identifier"]
        print(f"  {ts}  zone={zone['zone_id']}  {hit['path']}")
        if zone["host_url"] or zone["referrer_url"]:
            print(f"      host={zone['host_url']}  referrer={zone['referrer_url']}")
    if args.out:
        print(f"Report: {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
