"""Recover Tor-related file activity from NTFS metadata: $MFT and $UsnJrnl:$J.

The filesystem keeps its own record of what Tor Browser and the tor daemon
did to disk, independent of what those programs chose to persist:

  $MFT          one record per file, including DELETED files whose names and
                small (resident) contents survive until the record is reused.
                Zone.Identifier streams are resident, so a download's mark-of-
                the-web is recoverable here even after the file was removed.
  $UsnJrnl:$J   the change journal: a timestamped log of every create, write,
                rename, stream change and delete, by name. tor writes client-auth
                credentials as <onion>.auth_private (via a .tmp rename) and the
                profile databases on every session, so the journal yields both
                onion addresses and a minute-resolution activity timeline that
                outlives the files.

Both are exposed by ntfs-3g when the volume is mounted with
  -o ro,show_sys_files,streams_interface=windows
as <root>/$MFT and <root>/$Extend/$UsnJrnl:$J. Exported copies (ntfscat, TSK)
can be passed explicitly instead.

Usage:
    python analyze_ntfs_journal.py <mounted_volume_root> [--out report.json]
    python analyze_ntfs_journal.py --mft MFT.bin --usnjrnl J.bin [--out report.json]
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import re
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from modules.module_b_disk.analyze_downloads import parse_zone_identifier
from modules.module_b_disk.carve_onion_strings import ONION_RE
from modules.module_b_disk.onion import is_v3_onion

MFT_RECORD_SIZE = 1024
SECTOR = 512
ROOT_RECORD = 5
_FILETIME_EPOCH = dt.datetime(1601, 1, 1, tzinfo=dt.timezone.utc)

ATTR_STANDARD_INFORMATION = 0x10
ATTR_FILE_NAME = 0x30
ATTR_DATA = 0x80
ATTR_END = 0xFFFFFFFF
NAMESPACE_DOS = 2

USN_REASONS = {
    0x00000001: "DATA_OVERWRITE",
    0x00000002: "DATA_EXTEND",
    0x00000004: "DATA_TRUNCATION",
    0x00000010: "NAMED_DATA_OVERWRITE",
    0x00000020: "NAMED_DATA_EXTEND",
    0x00000040: "NAMED_DATA_TRUNCATION",
    0x00000100: "FILE_CREATE",
    0x00000200: "FILE_DELETE",
    0x00001000: "RENAME_OLD_NAME",
    0x00002000: "RENAME_NEW_NAME",
    0x00008000: "BASIC_INFO_CHANGE",
    0x00200000: "STREAM_CHANGE",
    0x80000000: "CLOSE",
}
NAMED_DATA_MASK = 0x00000070

AUTH_PRIVATE_RE = re.compile(r"^([a-z2-7]{56})\.auth_private(?:\.tmp)?$", re.IGNORECASE)
ONION_NAME_RE = re.compile(r"[a-z2-7]{56}", re.IGNORECASE)
TOR_PATH_RE = re.compile(r"tor ?browser|torbrowser", re.IGNORECASE)
TOR_DAEMON_FILES = {
    "state",
    "lock",
    "torrc",
    "cached-certs",
    "cached-microdesc-consensus",
    "cached-microdescs",
    "cached-microdescs.new",
    "unverified-microdesc-consensus",
    "onion-auth",
}
PROFILE_FILE_RE = re.compile(
    r"^(places|cookies|favicons|formhistory|storage|content-prefs|permissions)\.sqlite"
    r"(-wal|-shm|-journal)?$|^(prefs\.js|xulstore\.json|sessionstore.*|recovery\.(jsonlz4|baklz4)"
    r"|sessionCheckpoints\.json|onion-aliases\.json)$",
    re.IGNORECASE,
)
MAX_EVENTS = 5000
# Browsers write downloads to a temp name and rename on completion; the suffix
# identifies the family. Firefox (and so Tor Browser) uses 8 random characters
# plus the final extension plus ".part"; Chromium ".crdownload"; IE/old Edge ".partial".
TEMP_SUFFIXES = {".part": "firefox", ".crdownload": "chromium", ".partial": "ie_legacy_edge"}
FIREFOX_PART_RE = re.compile(r"^[A-Za-z0-9_-]{8}\..+\.part$")


def _filetime(value: int) -> str | None:
    if value == 0:
        return None
    return (_FILETIME_EPOCH + dt.timedelta(microseconds=value / 10)).isoformat()


def _apply_fixups(record: bytearray) -> bool:
    usa_offset, usa_count = struct.unpack_from("<HH", record, 4)
    if usa_count < 2 or usa_offset + usa_count * 2 > len(record):
        return False
    usn = record[usa_offset : usa_offset + 2]
    for i in range(1, usa_count):
        end = i * SECTOR
        if end > len(record):
            break
        if record[end - 2 : end] != usn:
            return False
        record[end - 2 : end] = record[usa_offset + i * 2 : usa_offset + i * 2 + 2]
    return True


def parse_mft_record(raw: bytes, number: int) -> dict | None:
    if raw[:4] != b"FILE":
        return None
    record = bytearray(raw)
    if not _apply_fixups(record):
        return None
    sequence, _links, attrs_offset, flags = struct.unpack_from("<HHHH", record, 16)
    base_ref = struct.unpack_from("<Q", record, 32)[0]
    entry = {
        "record": number,
        "sequence": sequence,
        "in_use": bool(flags & 0x01),
        "is_dir": bool(flags & 0x02),
        "extension_of": (base_ref & 0xFFFFFFFFFFFF) if base_ref else None,
        "name": None,
        "namespace": None,
        "parent": None,
        "created_utc": None,
        "modified_utc": None,
        "fn_created_utc": None,
        "size": None,
        "resident_data": None,
        "streams": {},
    }
    offset = attrs_offset
    while offset + 16 <= len(record):
        attr_type, length = struct.unpack_from("<II", record, offset)
        if attr_type == ATTR_END or length < 16 or offset + length > len(record):
            break
        non_resident = record[offset + 8]
        name_len = record[offset + 9]
        name_off = struct.unpack_from("<H", record, offset + 10)[0]
        attr_name = (
            record[offset + name_off : offset + name_off + name_len * 2].decode(
                "utf-16-le", errors="replace"
            )
            if name_len
            else ""
        )
        value = b""
        if not non_resident:
            value_len, value_off = struct.unpack_from("<IH", record, offset + 16)
            value = bytes(record[offset + value_off : offset + value_off + value_len])
        if attr_type == ATTR_STANDARD_INFORMATION and len(value) >= 16:
            created, modified = struct.unpack_from("<QQ", value, 0)
            entry["created_utc"] = _filetime(created)
            entry["modified_utc"] = _filetime(modified)
        elif attr_type == ATTR_FILE_NAME and len(value) >= 66:
            parent_ref = struct.unpack_from("<Q", value, 0)[0]
            fn_created = struct.unpack_from("<Q", value, 8)[0]
            real_size = struct.unpack_from("<Q", value, 48)[0]
            fname_len = value[64]
            namespace = value[65]
            fname = value[66 : 66 + fname_len * 2].decode("utf-16-le", errors="replace")
            # A file may carry both a DOS 8.3 name and a long name; keep the long one.
            if entry["name"] is None or (
                entry["namespace"] == NAMESPACE_DOS and namespace != NAMESPACE_DOS
            ):
                entry["name"] = fname
                entry["namespace"] = namespace
                entry["parent"] = parent_ref & 0xFFFFFFFFFFFF
                entry["fn_created_utc"] = _filetime(fn_created)
                entry["size"] = real_size
        elif attr_type == ATTR_DATA:
            if attr_name:
                if not non_resident:
                    entry["streams"][attr_name] = value
            elif not non_resident:
                entry["resident_data"] = value
            elif entry["size"] is None:
                entry["size"] = struct.unpack_from("<Q", record, offset + 48)[0]
        offset += length
    return entry


def parse_mft(path: Path) -> dict[int, dict]:
    records: dict[int, dict] = {}
    with path.open("rb") as fh:
        number = 0
        while True:
            raw = fh.read(MFT_RECORD_SIZE)
            if len(raw) < MFT_RECORD_SIZE:
                break
            entry = parse_mft_record(raw, number)
            if entry and entry["name"] is not None and entry["extension_of"] is None:
                records[number] = entry
            number += 1
    return records


def resolve_path(records: dict[int, dict], number: int) -> str:
    parts = []
    seen = set()
    current = number
    while current in records and current not in seen and current != ROOT_RECORD:
        seen.add(current)
        entry = records[current]
        parts.append(entry["name"])
        current = entry["parent"]
    if current != ROOT_RECORD:
        parts.append(f"<unresolved:{current}>")
    return "\\".join(reversed(parts))


def _is_tor_related(name: str, path: str) -> bool:
    return bool(
        TOR_PATH_RE.search(path)
        or AUTH_PRIVATE_RE.match(name)
        or name in TOR_DAEMON_FILES
        or PROFILE_FILE_RE.match(name)
    )


def analyze_mft_records(records: dict[int, dict]) -> dict:
    onion_files = []
    zone_streams = []
    resident_onions = []
    deleted_tor = []
    for number, entry in records.items():
        name = entry["name"]
        path = resolve_path(records, number)
        deleted = not entry["in_use"]
        match = AUTH_PRIVATE_RE.match(name) or ONION_NAME_RE.search(name)
        if match and is_v3_onion(match.group(1 if match.re is AUTH_PRIVATE_RE else 0)):
            onion_files.append(
                {
                    "onion_address": match.group(1 if match.re is AUTH_PRIVATE_RE else 0).lower()
                    + ".onion",
                    "name": name,
                    "path": path,
                    "record": number,
                    "deleted": deleted,
                    "created_utc": entry["created_utc"] or entry["fn_created_utc"],
                    "modified_utc": entry["modified_utc"],
                }
            )
        zone = entry["streams"].get("Zone.Identifier")
        if zone is not None:
            zone_streams.append(
                {
                    "name": name,
                    "path": path,
                    "record": number,
                    "deleted": deleted,
                    "size": entry["size"],
                    "created_utc": entry["created_utc"] or entry["fn_created_utc"],
                    "zone_identifier": parse_zone_identifier(zone),
                }
            )
        data = entry["resident_data"]
        if data:
            found = sorted(
                {
                    m.group(0).decode().lower()
                    for m in ONION_RE.finditer(data)
                    if is_v3_onion(m.group(0).decode())
                }
            )
            if found:
                resident_onions.append(
                    {
                        "name": name,
                        "path": path,
                        "record": number,
                        "deleted": deleted,
                        "size": len(data),
                        "onion_addresses": found,
                    }
                )
        if deleted and _is_tor_related(name, path):
            deleted_tor.append(
                {
                    "name": name,
                    "path": path,
                    "record": number,
                    "modified_utc": entry["modified_utc"],
                }
            )
    return {
        "records": len(records),
        "in_use": sum(1 for e in records.values() if e["in_use"]),
        "onion_filenames": onion_files,
        "zone_identifier_streams": zone_streams,
        "resident_onion_strings": resident_onions,
        "deleted_tor_files": deleted_tor[:MAX_EVENTS],
    }


def _iter_usn_records(path: Path):
    fd = os.open(path, os.O_RDONLY)
    try:
        size = os.fstat(fd).st_size
        pos = 0
        pending = b""
        while pos < size:
            try:
                data_pos = os.lseek(fd, pos, os.SEEK_DATA)
            except OSError:
                data_pos = pos
            if data_pos != pos:
                pending = b""
                pos = data_pos
            os.lseek(fd, pos, os.SEEK_SET)
            chunk = os.read(fd, 8 << 20)
            if not chunk:
                break
            pos += len(chunk)
            buf = pending + chunk
            offset = 0
            while offset + 60 <= len(buf):
                length = struct.unpack_from("<I", buf, offset)[0]
                if length == 0:
                    # Journal pages are zero-padded to their end; jump to the next
                    # non-zero byte, aligned down to the 8-byte record boundary.
                    remaining = buf[offset:]
                    stripped = remaining.lstrip(b"\x00")
                    if not stripped:
                        offset = len(buf)
                        continue
                    aligned = offset + (len(remaining) - len(stripped)) // 8 * 8
                    offset = aligned if aligned > offset else offset + 8
                    continue
                if length < 60 or length % 8:
                    offset += 8
                    continue
                if offset + length > len(buf):
                    break
                record = buf[offset : offset + length]
                major = struct.unpack_from("<H", record, 4)[0]
                if major == 2:
                    yield record
                offset += length
            pending = buf[offset:] if offset < len(buf) else b""
    finally:
        os.close(fd)


def parse_usn_record(record: bytes) -> dict | None:
    (
        file_ref,
        parent_ref,
        usn,
        timestamp,
        reason,
        _source,
        _security,
        _attributes,
        name_len,
        name_off,
    ) = struct.unpack_from("<QQQQIIIIHH", record, 8)
    name = record[name_off : name_off + name_len].decode("utf-16-le", errors="replace")
    if not name or "\x00" in name:
        return None
    return {
        "usn": usn,
        "time_utc": _filetime(timestamp),
        "reason": reason,
        "reasons": [label for bit, label in USN_REASONS.items() if reason & bit],
        "record": file_ref & 0xFFFFFFFFFFFF,
        "parent": parent_ref & 0xFFFFFFFFFFFF,
        "name": name,
    }


def _temp_family(name: str) -> str | None:
    lowered = name.lower()
    for suffix, family in TEMP_SUFFIXES.items():
        if lowered.endswith(suffix):
            if suffix == ".part" and not FIREFOX_PART_RE.match(name):
                return None
            return family
    return None


def analyze_usn(path: Path, records: dict[int, dict]) -> dict:
    total = 0
    first = last = None
    events = []
    onion_names: dict[str, dict] = {}
    downloads = []
    temp_created: dict[int, dict] = {}
    pending_rename: dict[int, dict] = {}
    recent_download: dict[int, dict] = {}
    path_cache: dict[int, str] = {}

    def parent_path(parent: int) -> str:
        if parent not in path_cache:
            path_cache[parent] = resolve_path(records, parent) if records else ""
        return path_cache[parent]

    for raw in _iter_usn_records(path):
        rec = parse_usn_record(raw)
        if rec is None:
            continue
        total += 1
        first = first or rec["time_utc"]
        last = rec["time_utc"] or last
        folder = parent_path(rec["parent"])
        full = f"{folder}\\{rec['name']}" if folder else rec["name"]
        match = AUTH_PRIVATE_RE.match(rec["name"])
        if match:
            address = match.group(1).lower() + ".onion"
            entry = onion_names.setdefault(
                address, {"onion_address": address, "first_seen_utc": rec["time_utc"], "events": 0}
            )
            entry["events"] += 1
            entry["last_seen_utc"] = rec["time_utc"]
            entry["path"] = full
        family = _temp_family(rec["name"])
        if family and rec["reason"] & 0x100:
            temp_created[rec["record"]] = {"time_utc": rec["time_utc"], "name": rec["name"]}
        if family and rec["reason"] & 0x1000:
            pending_rename[rec["record"]] = {"temp_name": rec["name"], "family": family}
        elif rec["reason"] & 0x2000 and rec["record"] in pending_rename:
            temp = pending_rename.pop(rec["record"])
            started = temp_created.pop(rec["record"], {})
            download = {
                "started_utc": started.get("time_utc"),
                "completed_utc": rec["time_utc"],
                "name": rec["name"],
                "path": full,
                "temp_name": temp["temp_name"],
                "browser_family": temp["family"],
                "zone_identifier_written_utc": None,
                "deleted_utc": None,
            }
            if len(downloads) < MAX_EVENTS:
                downloads.append(download)
            recent_download[rec["record"]] = download
        elif rec["record"] in recent_download:
            download = recent_download[rec["record"]]
            if rec["reason"] & NAMED_DATA_MASK and not download["zone_identifier_written_utc"]:
                download["zone_identifier_written_utc"] = rec["time_utc"]
            if rec["reason"] & 0x200:
                download["deleted_utc"] = rec["time_utc"]
        if _is_tor_related(rec["name"], full) and len(events) < MAX_EVENTS:
            events.append(
                {
                    "time_utc": rec["time_utc"],
                    "name": rec["name"],
                    "path": full,
                    "reasons": rec["reasons"],
                }
            )
    tor_times = [e["time_utc"] for e in events if e["time_utc"]]
    return {
        "records": total,
        "journal_first_utc": first,
        "journal_last_utc": last,
        "tor_events": events,
        "tor_activity_window": (
            {"first_utc": min(tor_times), "last_utc": max(tor_times), "events": len(events)}
            if tor_times
            else None
        ),
        "onion_filenames": sorted(onion_names.values(), key=lambda e: e["first_seen_utc"] or ""),
        "downloads": downloads,
    }


def locate(root: Path) -> tuple[Path | None, Path | None]:
    mft = root / "$MFT"
    usn = root / "$Extend" / "$UsnJrnl:$J"
    return (mft if mft.is_file() else None, usn if usn.is_file() else None)


def analyze_ntfs(
    root: Path | None = None, mft: Path | None = None, usnjrnl: Path | None = None
) -> dict:
    if root is not None:
        root = root.resolve(strict=True)
        found_mft, found_usn = locate(root)
        mft = mft or found_mft
        usnjrnl = usnjrnl or found_usn
    report: dict = {
        "sources": {"mft": str(mft) if mft else None, "usnjrnl": str(usnjrnl) if usnjrnl else None},
        "note": (
            "NTFS metadata is written by the filesystem driver, not by Tor Browser, and "
            "survives file deletion until the record or journal space is reused. Timestamps "
            "are NTFS UTC. Path resolution uses the current $MFT; a deleted parent shows as "
            "<unresolved>."
        ),
    }
    if not mft and not usnjrnl:
        report["error"] = (
            "no $MFT or $UsnJrnl:$J found; mount with "
            "-o ro,show_sys_files,streams_interface=windows or pass --mft/--usnjrnl"
        )
        return report
    records: dict[int, dict] = {}
    if mft:
        records = parse_mft(mft)
        report["mft"] = analyze_mft_records(records)
    if usnjrnl:
        report["usnjrnl"] = analyze_usn(usnjrnl, records)
    addresses: dict[str, dict] = {}

    def entry(address: str) -> dict:
        return addresses.setdefault(address, {"sources": set(), "deleted": False, "paths": []})

    for item in report.get("mft", {}).get("onion_filenames", []):
        found = entry(item["onion_address"])
        found["sources"].add("mft")
        found["deleted"] = found["deleted"] or item["deleted"]
        found["paths"].append(item["path"])
    for item in report.get("mft", {}).get("resident_onion_strings", []):
        for address in item["onion_addresses"]:
            found = entry(address)
            found["sources"].add("mft_resident_data")
            found["paths"].append(item["path"])
    for item in report.get("usnjrnl", {}).get("onion_filenames", []):
        found = entry(item["onion_address"])
        found["sources"].add("usnjrnl")
        found["paths"].append(item["path"])
    report["onion_addresses"] = {
        address: {
            "sources": sorted(v["sources"]),
            "deleted": v["deleted"],
            "paths": sorted(set(v["paths"])),
        }
        for address, v in sorted(addresses.items())
    }
    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root", type=Path, nargs="?", help="Mounted volume root (ntfs-3g)")
    parser.add_argument("--mft", type=Path, help="Exported $MFT")
    parser.add_argument("--usnjrnl", type=Path, help="Exported $UsnJrnl:$J stream")
    parser.add_argument("--out", type=Path, help="Write the JSON report here")
    args = parser.parse_args(argv)
    if not (args.root or args.mft or args.usnjrnl):
        parser.error("give a mounted root or --mft/--usnjrnl")
    try:
        report = analyze_ntfs(args.root, args.mft, args.usnjrnl)
    except (OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        with args.out.open("x", encoding="utf-8") as stream:
            json.dump(report, stream, indent=2)
    print("=== TRANCE Module B — NTFS metadata ===")
    if report.get("error"):
        print(f"error: {report['error']}", file=sys.stderr)
        return 1
    if "mft" in report:
        m = report["mft"]
        print(
            f"$MFT: {m['records']} named records, {m['in_use']} in use; "
            f"{len(m['onion_filenames'])} onion filename(s), "
            f"{len(m['zone_identifier_streams'])} Zone.Identifier stream(s), "
            f"{len(m['deleted_tor_files'])} deleted Tor-related file(s)"
        )
    if "usnjrnl" in report:
        u = report["usnjrnl"]
        window = u["tor_activity_window"]
        print(
            f"$UsnJrnl: {u['records']} records ({u['journal_first_utc']} to {u['journal_last_utc']}); "
            f"{len(u['tor_events'])} Tor-related event(s)"
            + (f", active {window['first_utc']} to {window['last_utc']}" if window else "")
        )
    for address, info in report["onion_addresses"].items():
        flag = "  [deleted]" if info["deleted"] else ""
        print(f"  {address}  via {', '.join(info['sources'])}{flag}")
    if args.out:
        print(f"Report: {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
