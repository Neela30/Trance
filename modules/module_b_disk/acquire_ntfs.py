"""NTFS metadata acquisition for Module B (Windows target, elevated).

    python -m modules.module_b_disk.acquire_ntfs --output-dir E:\\evidence\\disk\\ntfs

Exports, from a live volume, the files analyze_ntfs_journal.py and
analyze_memory_residue.py otherwise read from a mounted disk image -- so a
running target (including a BitLocker one: the volume device is read already
decrypted) needs no full-disk image for the deleted-file and memory-residue
analysis:

  MFT            the $MFT's unnamed $DATA stream: one record per file,
                 deleted ones included until reused
  UsnJrnl_J      $Extend\\$UsnJrnl:$J, the change journal. It is a sparse
                 stream with a nominal size in the tens of GB of which only
                 the newest tens of MB are allocated; only the allocated runs
                 are copied, back to back (USN records are self-describing, so
                 analyze_ntfs_journal parses the compact file unchanged). The
                 original stream offset of each run is kept in
                 ntfs_metadata.json.
  pagefile.sys,  paged-out process memory -- on by default
  swapfile.sys
  hiberfil.sys   the RAM image at hibernation -- opt-in (as large as RAM)

None of these can be copied as files: Windows holds them open exclusively, and
$J is not even reachable through the file API. They are read the way
ntfs-3g/TSK read an image: boot sector -> $MFT location -> each file's MFT
record -> its runlist -> clusters straight off the volume device.

$MFT and $J are read from a Volume Shadow Copy (point-in-time consistent),
created and deleted the same way module_a_registry.acquire does for
Amcache.hve; if the snapshot can't be made, the live volume is read instead and
ntfs_metadata.json records which. pagefile/swapfile/hiberfil are always read
from the live volume: VSS excludes them from snapshots.

Writes <output_dir>/<letter>/ per volume, each with ntfs_metadata.json and a
sha256sum-format hashes.sha256 (what evidence.verify_hashes() parses).
Standard library only, like the rest of the acquire side.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import shutil
import struct
import sys
import time
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path, PureWindowsPath
from typing import BinaryIO

from core.custody_log import CustodyEntry, CustodyLog
from core.exceptions import AcquisitionError

ATTR_ATTRIBUTE_LIST = 0x20
ATTR_FILE_NAME = 0x30
ATTR_DATA = 0x80
ATTR_END = 0xFFFFFFFF
FLAG_COMPRESSED = 0x0001
FLAG_ENCRYPTED = 0x4000
FIXUP_STRIDE = 512  # NTFS update-sequence stride, independent of the device's sector size
NAMESPACE_DOS = 2

MFT_RECORD = 0
ROOT_RECORD = 5
EXTEND_RECORD = 11

CHUNK = 4 << 20
FREE_SPACE_MARGIN = 512 << 20

MFT_FILENAME = "MFT"
USNJRNL_FILENAME = "UsnJrnl_J"
METADATA_FILENAME = "ntfs_metadata.json"
# (output name, name in the volume root, opt-in flag that enables it)
RESIDUE_FILES = (
    ("pagefile.sys", "include_pagefile"),
    ("swapfile.sys", "include_pagefile"),
    ("hiberfil.sys", "include_hiberfil"),
)


@dataclass(frozen=True)
class BootSector:
    bytes_per_sector: int
    cluster_size: int
    mft_lcn: int
    record_size: int
    total_sectors: int
    serial: str


def parse_boot_sector(raw: bytes) -> BootSector:
    if len(raw) < 512 or raw[3:11] != b"NTFS    ":
        raise AcquisitionError("not an NTFS volume (boot sector OEM id is not 'NTFS    ')")
    bytes_per_sector = struct.unpack_from("<H", raw, 0x0B)[0]
    spc = raw[0x0D]
    # Values above 0x80 encode 2**(256 - n) sectors (needed for clusters > 64 KiB).
    sectors_per_cluster = 1 << (256 - spc) if spc > 0x80 else spc
    total_sectors, mft_lcn = struct.unpack_from("<QQ", raw, 0x28)
    per_record = struct.unpack_from("<b", raw, 0x40)[0]
    cluster_size = bytes_per_sector * sectors_per_cluster
    record_size = 1 << -per_record if per_record < 0 else per_record * cluster_size
    serial = struct.unpack_from("<Q", raw, 0x48)[0]
    if bytes_per_sector not in (512, 1024, 2048, 4096) or not cluster_size or not record_size:
        raise AcquisitionError("NTFS boot sector has an implausible geometry")
    return BootSector(
        bytes_per_sector=bytes_per_sector,
        cluster_size=cluster_size,
        mft_lcn=mft_lcn,
        record_size=record_size,
        total_sectors=total_sectors,
        serial=f"{serial:016X}",
    )


def apply_fixups(record: bytearray) -> bool:
    """Restore the last two bytes of every 512-byte stride from the update sequence
    array; False if a stride's check value doesn't match (torn or not a record)."""
    usa_offset, usa_count = struct.unpack_from("<HH", record, 4)
    if usa_count < 2 or usa_offset + usa_count * 2 > len(record):
        return False
    check = record[usa_offset : usa_offset + 2]
    for i in range(1, usa_count):
        end = i * FIXUP_STRIDE
        if end > len(record):
            break
        if record[end - 2 : end] != check:
            return False
        record[end - 2 : end] = record[usa_offset + i * 2 : usa_offset + i * 2 + 2]
    return True


def decode_runlist(data: bytes) -> list[tuple[int | None, int]]:
    """[(lcn, cluster_count)], lcn None for a sparse run. Each run's LCN is stored as a
    signed delta from the previous one; an offset field of size 0 means sparse."""
    runs: list[tuple[int | None, int]] = []
    pos = 0
    lcn = 0
    while pos < len(data) and data[pos]:
        header = data[pos]
        len_size, off_size = header & 0x0F, header >> 4
        pos += 1
        if not len_size or pos + len_size + off_size > len(data):
            raise AcquisitionError("malformed NTFS runlist")
        length = int.from_bytes(data[pos : pos + len_size], "little")
        pos += len_size
        if off_size:
            lcn += int.from_bytes(data[pos : pos + off_size], "little", signed=True)
            runs.append((lcn, length))
        else:
            runs.append((None, length))
        pos += off_size
    return runs


@dataclass
class Attribute:
    type: int
    name: str
    flags: int
    non_resident: bool
    value: bytes = b""  # resident content
    start_vcn: int = 0
    runs: list[tuple[int | None, int]] | None = None
    real_size: int = 0
    initialized_size: int = 0


def iter_attributes(record: bytes) -> Iterator[Attribute]:
    offset = struct.unpack_from("<H", record, 20)[0]
    while offset + 16 <= len(record):
        attr_type, length = struct.unpack_from("<II", record, offset)
        if attr_type == ATTR_END or length < 16 or offset + length > len(record):
            return
        non_resident = bool(record[offset + 8])
        name_len = record[offset + 9]
        name_off, flags = struct.unpack_from("<HH", record, offset + 10)
        name = (
            record[offset + name_off : offset + name_off + name_len * 2].decode(
                "utf-16-le", errors="replace"
            )
            if name_len
            else ""
        )
        if non_resident:
            start_vcn = struct.unpack_from("<Q", record, offset + 16)[0]
            runlist_off = struct.unpack_from("<H", record, offset + 32)[0]
            real_size, initialized = struct.unpack_from("<QQ", record, offset + 48)
            yield Attribute(
                attr_type,
                name,
                flags,
                True,
                start_vcn=start_vcn,
                runs=decode_runlist(bytes(record[offset + runlist_off : offset + length])),
                real_size=real_size,
                initialized_size=initialized,
            )
        else:
            value_len, value_off = struct.unpack_from("<IH", record, offset + 16)
            value = bytes(record[offset + value_off : offset + value_off + value_len])
            yield Attribute(attr_type, name, flags, False, value=value, real_size=len(value))
        offset += length


def parse_attribute_list(content: bytes) -> list[dict]:
    entries = []
    pos = 0
    while pos + 26 <= len(content):
        attr_type, length = struct.unpack_from("<IH", content, pos)
        if length < 26:
            break
        name_len, name_off = content[pos + 6], content[pos + 7]
        start_vcn, ref = struct.unpack_from("<QQ", content, pos + 8)
        name = content[pos + name_off : pos + name_off + name_len * 2].decode(
            "utf-16-le", errors="replace"
        )
        entries.append(
            {
                "type": attr_type,
                "name": name,
                "start_vcn": start_vcn,
                "record": ref & 0xFFFFFFFFFFFF,
            }
        )
        pos += length
    return entries


def record_file_name(record: bytes) -> tuple[str, int] | None:
    """(long name, parent record) from a fixed-up record's $FILE_NAME attributes."""
    best: tuple[str, int, int] | None = None
    for attr in iter_attributes(record):
        if attr.type != ATTR_FILE_NAME or attr.non_resident or len(attr.value) < 66:
            continue
        parent = struct.unpack_from("<Q", attr.value, 0)[0] & 0xFFFFFFFFFFFF
        name_len, namespace = attr.value[64], attr.value[65]
        name = attr.value[66 : 66 + name_len * 2].decode("utf-16-le", errors="replace")
        if best is None or (best[2] == NAMESPACE_DOS and namespace != NAMESPACE_DOS):
            best = (name, parent, namespace)
    return (best[0], best[1]) if best else None


@dataclass
class Stream:
    """One file's $DATA stream, its runs merged across attribute-list extents."""

    runs: list[tuple[int | None, int]]
    real_size: int
    initialized_size: int
    flags: int


class NtfsVolume:
    """Read-only view of an NTFS volume through a file object: a raw volume device
    (\\\\.\\C:, a shadow-copy device) on the target, or an image file in tests.
    `base` is the volume's byte offset within that file (0 for a volume device).

    Every device read is aligned to the cluster size: raw volume handles on Windows
    reject reads that aren't sector-aligned, and a cluster is always a whole number
    of sectors."""

    def __init__(self, fh: BinaryIO, base: int = 0):
        self.fh = fh
        self.base = base
        self.fh.seek(base)
        # 4096, not 512: a 4Kn device rejects a 512-byte read of sector 0.
        self.boot = parse_boot_sector(self.fh.read(4096))
        self.cluster_size = self.boot.cluster_size
        self.record_size = self.boot.record_size
        # Bootstrap: record 0 sits at the start of the $MFT, so the boot sector's LCN
        # alone reaches it. Its first $DATA extent maps the start of the $MFT -- enough
        # to reach any extension records a fragmented $MFT's attribute list points at
        # -- and the full runlist then maps every record.
        self.mft_runs: list[tuple[int | None, int]] = [
            (self.boot.mft_lcn, max(1, -(-self.record_size // self.cluster_size)))
        ]
        first = next(
            (
                a
                for a in iter_attributes(self.read_record(MFT_RECORD))
                if a.type == ATTR_DATA and not a.name and a.non_resident and a.start_vcn == 0
            ),
            None,
        )
        if first is None:
            raise AcquisitionError("$MFT record 0 has no first $DATA extent")
        self.mft_runs = first.runs or []
        self.mft = self.stream(MFT_RECORD)
        self.mft_runs = self.mft.runs

    def read(self, offset: int, size: int) -> bytes:
        align = self.cluster_size
        start = offset - offset % align
        end = offset + size
        end += (-end) % align
        self.fh.seek(self.base + start)
        data = self.fh.read(end - start)
        return data[offset - start : offset - start + size]

    def read_clusters(self, lcn: int, count: int) -> bytes:
        return self.read(lcn * self.cluster_size, count * self.cluster_size)

    def _mft_offset(self, number: int) -> int:
        target = number * self.record_size
        vcn_bytes = 0
        for lcn, length in self.mft_runs:
            run_bytes = length * self.cluster_size
            if target < vcn_bytes + run_bytes:
                if lcn is None:
                    break
                return lcn * self.cluster_size + target - vcn_bytes
            vcn_bytes += run_bytes
        raise AcquisitionError(f"MFT record {number} is outside the $MFT's runlist")

    def read_record(self, number: int) -> bytearray:
        record = bytearray(self.read(self._mft_offset(number), self.record_size))
        if record[:4] != b"FILE" or not apply_fixups(record):
            raise AcquisitionError(f"MFT record {number} is not a valid FILE record")
        return record

    def stream(self, number: int, name: str = "") -> Stream:
        """The runlist of record `number`'s $DATA stream `name` ("" = unnamed), following
        an $ATTRIBUTE_LIST into extension records when the stream is too fragmented to
        fit in one record (true of a large $MFT and of a busy $J)."""
        base = self.read_record(number)
        attrs = list(iter_attributes(base))
        attr_list = next((a for a in attrs if a.type == ATTR_ATTRIBUTE_LIST), None)
        if attr_list is None:
            extents = [a for a in attrs if a.type == ATTR_DATA and a.name == name]
        else:
            content = (
                self._read_stream_bytes(
                    Stream(attr_list.runs or [], attr_list.real_size, attr_list.initialized_size, 0)
                )
                if attr_list.non_resident
                else attr_list.value
            )
            records = {number: base}
            extents = []
            wanted = [
                e
                for e in parse_attribute_list(content)
                if e["type"] == ATTR_DATA and e["name"] == name
            ]
            for entry in wanted:
                if entry["record"] not in records:
                    records[entry["record"]] = self.read_record(entry["record"])
                for attr in iter_attributes(records[entry["record"]]):
                    if (
                        attr.type == ATTR_DATA
                        and attr.name == name
                        and attr.start_vcn == entry["start_vcn"]
                        and attr not in extents
                    ):
                        extents.append(attr)
        if not extents:
            raise AcquisitionError(f"MFT record {number} has no $DATA stream {name!r}")
        first = min(extents, key=lambda a: a.start_vcn)
        if not first.non_resident:
            raise AcquisitionError(f"MFT record {number} stream {name!r} is resident")
        runs: list[tuple[int | None, int]] = []
        vcn = 0
        for attr in sorted(extents, key=lambda a: a.start_vcn):
            if attr.start_vcn != vcn:
                raise AcquisitionError(
                    f"MFT record {number} stream {name!r}: extent starts at VCN "
                    f"{attr.start_vcn}, expected {vcn}"
                )
            runs.extend(attr.runs or [])
            vcn += sum(length for _, length in attr.runs or [])
        return Stream(runs, first.real_size, first.initialized_size, first.flags)

    def _read_stream_bytes(self, stream: Stream) -> bytes:
        out = bytearray()
        for lcn, length in stream.runs:
            if len(out) >= stream.real_size:
                break
            out += (
                bytes(length * self.cluster_size)
                if lcn is None
                else self.read_clusters(lcn, length)
            )
        return bytes(out[: stream.real_size])

    def copy_stream(self, stream: Stream, out: BinaryIO, compact: bool = False) -> dict:
        """Write the stream to `out`. compact=False reproduces it byte for byte (sparse
        runs as zeros); compact=True writes only allocated runs, back to back, and
        returns where each came from. Bytes past the initialized size read as zeros,
        as NTFS itself returns them."""
        if stream.flags & (FLAG_COMPRESSED | FLAG_ENCRYPTED):
            raise AcquisitionError("stream is NTFS-compressed or EFS-encrypted; not supported")
        cs = self.cluster_size
        written = 0
        sparse_skipped = 0
        extents = []
        stream_off = 0
        for lcn, length in stream.runs:
            if stream_off >= stream.real_size:
                break
            take = min(length * cs, stream.real_size - stream_off)
            if lcn is None:
                if compact:
                    sparse_skipped += take
                else:
                    _write_zeros(out, take)
                    written += take
            else:
                if compact:
                    extents.append(
                        {"stream_offset": stream_off, "file_offset": written, "length": take}
                    )
                done = 0
                while done < take:
                    step = min(CHUNK, take - done)
                    chunk = bytearray(self.read(lcn * cs + done, step))
                    if len(chunk) != step:
                        raise AcquisitionError("short read from the volume device")
                    uninit = stream.initialized_size - (stream_off + done)
                    if uninit < step:
                        chunk[max(0, uninit) :] = bytes(step - max(0, uninit))
                    out.write(chunk)
                    done += step
                written += take
            stream_off += take
        if not compact and written < stream.real_size:
            _write_zeros(out, stream.real_size - written)
            written = stream.real_size
        result = {"bytes_written": written, "stream_size": stream.real_size}
        if compact:
            result["sparse_bytes_skipped"] = sparse_skipped
            result["extents"] = extents
        return result


def _write_zeros(out: BinaryIO, count: int) -> None:
    while count > 0:
        step = min(CHUNK, count)
        out.write(bytes(step))
        count -= step


def find_records(mft_path: Path, record_size: int, wanted: dict[str, int]) -> dict[str, int]:
    """Record numbers of in-use files named `wanted` (name -> parent record) in an
    exported $MFT. A UTF-16 substring search picks candidate records cheaply; a full
    parse only runs if a name could straddle a fixup position and hide from it."""
    found: dict[str, int] = {}
    lowered = {name.lower(): (name, parent) for name, parent in wanted.items()}

    def consider(number: int, raw: bytes) -> None:
        record = bytearray(raw)
        if record[:4] != b"FILE" or not apply_fixups(record):
            return
        flags = struct.unpack_from("<H", record, 22)[0]
        base_ref = struct.unpack_from("<Q", record, 32)[0]
        if not flags & 0x01 or base_ref:
            return
        named = record_file_name(record)
        if named and named[0].lower() in lowered:
            name, parent = lowered[named[0].lower()]
            if named[1] == parent and name not in found:
                found[name] = number

    def scan(full: bool) -> None:
        needles = [name.encode("utf-16-le") for name in wanted]
        with mft_path.open("rb") as fh:
            number = 0
            while len(found) < len(wanted):
                block = fh.read(record_size * 4096)
                if not block:
                    break
                for i in range(len(block) // record_size):
                    raw = block[i * record_size : (i + 1) * record_size]
                    if full or any(n in raw for n in needles):
                        consider(number + i, raw)
                number += len(block) // record_size

    scan(full=False)
    if len(found) < len(wanted):
        scan(full=True)
    return found


def _iso_now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat()


def normalize_drive(value: str) -> str:
    """ "C", "c:", "C:\\" and any path on that drive all give "C:"."""
    if len(value) == 1:
        value += ":"
    drive = PureWindowsPath(value if value.endswith(("\\", "/")) else value + "\\").drive
    if len(drive) != 2 or drive[1] != ":" or not drive[0].isalpha():
        raise AcquisitionError(f"not a drive letter: {value!r}")
    return drive.upper()


def system_drive() -> str:
    return normalize_drive(os.environ.get("SystemDrive", "C:"))


def _open_device(path: str) -> BinaryIO:
    try:
        return open(path, "rb", buffering=0)
    except OSError as exc:
        raise AcquisitionError(f"Could not open {path} for raw reading: {exc}") from exc


def _create_snapshot(drive: str) -> tuple[str, str]:
    # Reuses Module A's WMI create / vssadmin delete pair (see its module docstring for
    # why creation can't go through vssadmin on client Windows).
    from modules.module_a_registry.acquire import _create_shadow_copy

    return _create_shadow_copy(drive)


def _delete_snapshot(shadow_id: str) -> None:
    from modules.module_a_registry.acquire import _delete_shadow_copy

    _delete_shadow_copy(shadow_id)


def _same_volume(path: Path, drive: str) -> bool:
    try:
        return normalize_drive(str(path.resolve())) == drive
    except AcquisitionError:
        return False


def _copy_metafiles(volume: NtfsVolume, dest: Path, meta: dict) -> None:
    """$MFT (byte for byte) and $UsnJrnl:$J (allocated runs only) off one volume."""
    with (dest / MFT_FILENAME).open("wb") as out:
        meta["mft"] = volume.copy_stream(volume.mft, out)
    meta["mft"]["file"] = MFT_FILENAME
    usn = find_records(dest / MFT_FILENAME, volume.record_size, {"$UsnJrnl": EXTEND_RECORD})
    if "$UsnJrnl" not in usn:
        meta["usnjrnl"] = {"status": "missing", "message": "no $UsnJrnl (journal disabled?)"}
        return
    stream = volume.stream(usn["$UsnJrnl"], "$J")
    with (dest / USNJRNL_FILENAME).open("wb") as out:
        meta["usnjrnl"] = {
            "status": "ok",
            "file": USNJRNL_FILENAME,
            "record": usn["$UsnJrnl"],
            **volume.copy_stream(stream, out, compact=True),
        }


def acquire_volume(
    drive: str,
    output_dir: Path,
    *,
    use_vss: bool = True,
    include_pagefile: bool = True,
    include_hiberfil: bool = False,
) -> dict:
    """Export one volume's NTFS metadata (and memory-residue files) to output_dir/<letter>."""
    drive = normalize_drive(drive)
    dest = output_dir / drive[0]
    dest.mkdir(parents=True, exist_ok=True)
    meta: dict = {
        "drive": drive,
        "captured_at_utc": _iso_now(),
        "output_on_source_volume": _same_volume(dest, drive),
        "warnings": [],
    }
    if meta["output_on_source_volume"]:
        meta["warnings"].append(
            f"output is on {drive} itself: writing it may overwrite deleted data on the "
            "volume being examined; use external media"
        )
    live_path = f"\\\\.\\{drive}"

    shadow_id = None
    source_path = live_path
    meta["metafile_source"] = "live"
    if use_vss:
        try:
            shadow_id, source_path = _create_snapshot(drive)
            meta["metafile_source"] = "vss"
            meta["shadow_device"] = source_path
        except AcquisitionError as exc:
            meta["vss_error"] = str(exc)
            meta["warnings"].append(
                "shadow copy unavailable; $MFT/$J read from the live volume, so a file "
                "changing during the copy may be captured inconsistently"
            )
    try:
        with _open_device(source_path) as fh:
            volume = NtfsVolume(fh)
            meta["boot_sector"] = {
                "bytes_per_sector": volume.boot.bytes_per_sector,
                "cluster_size": volume.cluster_size,
                "mft_record_size": volume.record_size,
                "mft_lcn": volume.boot.mft_lcn,
                "volume_serial": volume.boot.serial,
            }
            _copy_metafiles(volume, dest, meta)
    finally:
        if shadow_id:
            _delete_snapshot(shadow_id)

    flags = {"include_pagefile": include_pagefile, "include_hiberfil": include_hiberfil}
    wanted = [name for name, flag in RESIDUE_FILES if flags[flag]]
    meta["residue_files"] = {}
    if wanted:
        records = find_records(
            dest / MFT_FILENAME, volume.record_size, {n: ROOT_RECORD for n in wanted}
        )
        with _open_device(live_path) as fh:
            live = NtfsVolume(fh)
            for name in wanted:
                meta["residue_files"][name] = _copy_residue_file(
                    live, records.get(name), name, dest
                )
    for name, flag in RESIDUE_FILES:
        if not flags[flag]:
            meta["residue_files"].setdefault(
                name, {"status": "skipped", "message": "not requested"}
            )
    (dest / METADATA_FILENAME).write_text(json.dumps(meta, indent=2), encoding="utf-8")
    return meta


def _copy_residue_file(live: NtfsVolume, number: int | None, name: str, dest: Path) -> dict:
    if number is None:
        return {"status": "missing", "message": f"no {name} in the volume root"}
    try:
        record = live.read_record(number)
        named = record_file_name(record)
        if not named or named[0].lower() != name.lower():
            # The record was reused between the snapshot and now.
            return {"status": "error", "message": f"MFT record {number} is no longer {name}"}
        stream = live.stream(number)
        free = shutil.disk_usage(dest).free
        if stream.real_size + FREE_SPACE_MARGIN > free:
            return {
                "status": "skipped",
                "message": f"needs {stream.real_size:,} bytes, only {free:,} free on the "
                "output drive",
            }
        print(f"[*] ntfs: copying {name} ({stream.real_size / (1 << 30):.1f} GiB) ...")
        with (dest / name).open("wb") as out:
            result = live.copy_stream(stream, out)
        return {"status": "ok", "file": name, "record": number, **result}
    except (AcquisitionError, OSError) as exc:
        (dest / name).unlink(missing_ok=True)
        return {"status": "error", "message": f"{type(exc).__name__}: {exc}"}


def _timestamp() -> str:
    return time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())


def acquire_all(
    drives: list[str],
    output_dir: Path,
    *,
    use_vss: bool = True,
    include_pagefile: bool = True,
    include_hiberfil: bool = False,
) -> dict:
    """Each volume is isolated: one failing doesn't stop the others. status is "ok"
    if at least one volume's $MFT was exported."""
    from modules.module_b_disk.acquire import _manifest_entries, write_hash_manifest

    output_dir.mkdir(parents=True, exist_ok=True)
    custody = CustodyLog(output_dir / f"ntfs_acquire_{_timestamp()}.custody.json")
    volumes: dict[str, dict] = {}
    for drive in dict.fromkeys(normalize_drive(d) for d in drives):
        print(f"[*] ntfs: exporting $MFT/$UsnJrnl from {drive} ...")
        try:
            meta = acquire_volume(
                drive,
                output_dir,
                use_vss=use_vss,
                include_pagefile=include_pagefile,
                include_hiberfil=include_hiberfil,
            )
        except (AcquisitionError, OSError) as exc:
            volumes[drive[0]] = {"status": "error", "message": f"{type(exc).__name__}: {exc}"}
            print(f"[!] ntfs {drive}: {exc}", file=sys.stderr)
            continue
        for warning in meta["warnings"]:
            print(f"[!] ntfs {drive}: {warning}", file=sys.stderr)
        dest = output_dir / drive[0]
        manifest = write_hash_manifest(dest)
        for name, digest in _manifest_entries(manifest):
            custody.record(
                CustodyEntry(
                    artifact_path=str(dest / name),
                    sha256=digest,
                    action="acquire",
                    notes=f"NTFS metadata from {drive} raw volume read "
                    f"({meta['metafile_source']} for $MFT/$J)",
                )
            )
        volumes[drive[0]] = {
            "status": "ok",
            "path": str(dest),
            "metafile_source": meta["metafile_source"],
            "usnjrnl": meta["usnjrnl"].get("status"),
            "residue_files": {k: v["status"] for k, v in meta["residue_files"].items()},
        }
    custody.save()
    ok = any(v["status"] == "ok" for v in volumes.values())
    return {
        "status": "ok" if ok else "error",
        "path": str(output_dir),
        "volumes": volumes,
        "custody_log_path": str(custody.log_path),
        **({} if ok else {"message": "no volume's NTFS metadata could be exported"}),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Export $MFT, $UsnJrnl:$J and pagefile/swapfile from live NTFS volumes "
        "(Windows, elevated) for Module B."
    )
    parser.add_argument("--output-dir", type=Path, default=Path("captures/disk/ntfs"))
    parser.add_argument(
        "--volume", action="append", help="Drive letter, repeatable (default: system drive)"
    )
    parser.add_argument("--no-vss", action="store_true", help="Read $MFT/$J from the live volume")
    parser.add_argument("--skip-pagefile", action="store_true")
    parser.add_argument("--include-hiberfil", action="store_true")
    args = parser.parse_args(argv)
    if sys.platform != "win32":
        print("[!] NTFS acquisition only runs on Windows.", file=sys.stderr)
        return 1
    try:
        result = acquire_all(
            args.volume or [system_drive()],
            args.output_dir,
            use_vss=not args.no_vss,
            include_pagefile=not args.skip_pagefile,
            include_hiberfil=args.include_hiberfil,
        )
    except AcquisitionError as exc:
        print(f"[!] {exc}", file=sys.stderr)
        return 1
    print(json.dumps(result, indent=2))
    return 0 if result["status"] == "ok" else 1


if __name__ == "__main__":
    raise SystemExit(main())
