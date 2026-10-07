"""acquire_ntfs.py: raw NTFS reading (boot sector, runlists, attribute lists, fixups),
the per-volume export, and the analysis side reading that export back.

The synthetic volume below is built byte by byte so every structure the reader must
handle is present on purpose: a $MFT fragmented across two extents whose second
extent lives in an extension record (attribute list), a sparse $UsnJrnl:$J, a
pagefile with a negative LCN delta and an uninitialized tail, and a deleted record
carrying the same name as a live one."""

import datetime as dt
import hashlib
import io
import shutil
import struct
import subprocess
from collections import namedtuple
from pathlib import Path

import pytest

import acquire_all
import analyze_evidence
from core.config import TranceConfig
from core.exceptions import AcquisitionError
from modules.module_b_disk import acquire_ntfs
from modules.module_b_disk import run as run_disk_module
from modules.module_b_disk.evidence import verify_hashes

CS = 1024  # 512-byte sectors, 2 per cluster
RECORD = 1024
ONION = "jnagl5n7q47bdox4zscwgfyxcqsliulrh34qnexorwjwpbn37avtcdqd"
T0 = dt.datetime(2026, 9, 19, 8, 0, tzinfo=dt.timezone.utc)
J_REAL_SIZE = 9 * CS - 100
PAGEFILE_REAL, PAGEFILE_INIT = 3 * CS - 10, 2 * CS


def _filetime(moment):
    return int((moment - dt.datetime(1601, 1, 1, tzinfo=dt.timezone.utc)).total_seconds() * 1e7)


def _signed_size(value):
    for size in range(1, 9):
        if -(1 << (8 * size - 1)) <= value < (1 << (8 * size - 1)):
            return size
    raise ValueError(value)


def encode_runlist(runs):
    out = bytearray()
    previous = 0
    for lcn, length in runs:
        len_bytes = length.to_bytes(max(1, (length.bit_length() + 7) // 8), "little")
        if lcn is None:
            out += bytes([len(len_bytes)]) + len_bytes
            continue
        delta = lcn - previous
        size = _signed_size(delta)
        out += bytes([len(len_bytes) | size << 4]) + len_bytes
        out += delta.to_bytes(size, "little", signed=True)
        previous = lcn
    return bytes(out) + b"\x00"


def _align(n):
    return n + (-n) % 8


def resident(attr_type, value, name=""):
    name_bytes = name.encode("utf-16-le")
    value_off = _align(24 + len(name_bytes))
    length = _align(value_off + len(value))
    out = bytearray(length)
    struct.pack_into("<IIBBHHH", out, 0, attr_type, length, 0, len(name), 24, 0, 0)
    struct.pack_into("<IH", out, 16, len(value), value_off)
    out[24 : 24 + len(name_bytes)] = name_bytes
    out[value_off : value_off + len(value)] = value
    return bytes(out)


def non_resident(attr_type, runs, real, init=None, name="", start_vcn=0, flags=0):
    name_bytes = name.encode("utf-16-le")
    runlist = encode_runlist(runs)
    runlist_off = _align(64 + len(name_bytes))
    length = _align(runlist_off + len(runlist))
    clusters = sum(n for _, n in runs)
    out = bytearray(length)
    struct.pack_into("<IIBBHHH", out, 0, attr_type, length, 1, len(name), 64, flags, 0)
    struct.pack_into("<QQHH", out, 16, start_vcn, start_vcn + clusters - 1, runlist_off, 0)
    struct.pack_into("<QQQ", out, 40, clusters * CS, real, real if init is None else init)
    out[64 : 64 + len(name_bytes)] = name_bytes
    out[runlist_off : runlist_off + len(runlist)] = runlist
    return bytes(out)


def file_name(name, parent):
    encoded = name.encode("utf-16-le")
    value = struct.pack("<QQQQQQQII", parent | 1 << 48, *[_filetime(T0)] * 4, 0, 0, 0, 0)
    value += bytes([len(name), 1]) + encoded
    return resident(0x30, value)


def attribute_list(entries):
    out = bytearray()
    for attr_type, start_vcn, record in entries:
        entry = bytearray(32)
        struct.pack_into("<IHBBQQH", entry, 0, attr_type, 32, 0, 26, start_vcn, record | 1 << 48, 0)
        out += entry
    return resident(0x20, bytes(out))


def mft_record(number, attrs, in_use=True, is_dir=False, base_ref=0):
    rec = bytearray(RECORD)
    rec[0:4] = b"FILE"
    struct.pack_into("<HH", rec, 4, 48, 3)
    flags = (0x01 if in_use else 0) | (0x02 if is_dir else 0)
    struct.pack_into("<HHHHII", rec, 16, 1, 1, 56, flags, 56 + len(attrs) + 8, RECORD)
    struct.pack_into("<QHHI", rec, 32, base_ref, 0, 0, number)
    rec[56 : 56 + len(attrs)] = attrs
    struct.pack_into("<I", rec, 56 + len(attrs), 0xFFFFFFFF)
    struct.pack_into("<H", rec, 48, 0x0707)
    for i in (1, 2):
        rec[48 + i * 2 : 50 + i * 2] = rec[i * 512 - 2 : i * 512]
        struct.pack_into("<H", rec, i * 512 - 2, 0x0707)
    return bytes(rec)


def usn_record(usn, ref, parent, moment, reason, name):
    encoded = name.encode("utf-16-le")
    length = _align(60 + len(encoded))
    out = bytearray(length)
    struct.pack_into("<IHH", out, 0, length, 2, 0)
    struct.pack_into(
        "<QQQQIIIIHH",
        out,
        8,
        ref | 1 << 48,
        parent | 1 << 48,
        usn,
        _filetime(moment),
        reason,
        0,
        0,
        0x20,
        len(encoded),
        60,
    )
    out[60 : 60 + len(encoded)] = encoded
    return bytes(out)


def boot_sector(mft_lcn=8, total_sectors=256):
    raw = bytearray(512)
    raw[3:11] = b"NTFS    "
    struct.pack_into("<HB", raw, 0x0B, 512, 2)
    struct.pack_into("<QQQ", raw, 0x28, total_sectors, mft_lcn, 2)
    raw[0x40] = 0xF6  # -10: 2**10-byte records
    struct.pack_into("<Q", raw, 0x48, 0x1122334455667788)
    raw[510:512] = b"\x55\xaa"
    return raw


def build_volume() -> bytes:
    image = bytearray(128 * CS)
    image[0:512] = boot_sector()
    mft_runs_a, mft_runs_b = [(8, 8)], [(32, 8)]
    records = {
        0: mft_record(
            0,
            file_name("$MFT", 5)
            + attribute_list([(0x30, 0, 0), (0x80, 0, 0), (0x80, 8, 3)])
            + non_resident(0x80, mft_runs_a, 16 * RECORD),
        ),
        # Extension record holding the $MFT's second extent (VCN 8 onward).
        3: mft_record(3, non_resident(0x80, mft_runs_b, 16 * RECORD, start_vcn=8), base_ref=0),
        5: mft_record(5, file_name(".", 5), is_dir=True),
        # A deleted record with a live file's name, earlier in the $MFT: must be skipped.
        9: mft_record(9, file_name("pagefile.sys", 5), in_use=False),
        11: mft_record(11, file_name("$Extend", 5), is_dir=True),
        12: mft_record(
            12,
            file_name("$UsnJrnl", 11)
            + non_resident(0x80, [(None, 4), (60, 2), (None, 2), (70, 1)], J_REAL_SIZE, name="$J"),
        ),
        13: mft_record(
            13,
            file_name("pagefile.sys", 5)
            + non_resident(0x80, [(80, 2), (50, 1)], PAGEFILE_REAL, PAGEFILE_INIT),
        ),
    }
    for number, raw in records.items():
        lcn = 8 + number if number < 8 else 32 + number - 8
        image[lcn * CS : (lcn + 1) * CS] = raw
    journal = usn_record(1, 99, 5, T0, 0x100, "state") + usn_record(
        2, 99, 5, T0 + dt.timedelta(minutes=5), 0x2, "state"
    )
    image[60 * CS : 60 * CS + len(journal)] = journal
    image[70 * CS : 71 * CS] = b"J" * CS
    image[80 * CS : 81 * CS] = (f"x{ONION}.onion".encode()).ljust(CS, b"\x00")
    image[81 * CS : 82 * CS] = b"P" * CS
    image[50 * CS : 51 * CS] = b"Q" * CS
    return bytes(image)


def _cluster(image, lcn, count=1):
    return image[lcn * CS : (lcn + count) * CS]


# --- parsing primitives ---------------------------------------------------------------


def test_runlist_decodes_sparse_runs_and_negative_deltas():
    runs = [(100, 3), (None, 7), (40, 300), (70000, 1)]
    assert acquire_ntfs.decode_runlist(encode_runlist(runs)) == runs


def test_runlist_rejects_truncated_data():
    with pytest.raises(AcquisitionError):
        acquire_ntfs.decode_runlist(b"\x21\x05")


def test_boot_sector_geometry_including_large_cluster_encoding():
    boot = acquire_ntfs.parse_boot_sector(boot_sector())
    assert (boot.cluster_size, boot.record_size, boot.mft_lcn) == (1024, 1024, 8)
    raw = boot_sector()
    raw[0x0D] = 0xF8  # 2**(256-0xF8) = 256 sectors per cluster (128 KiB)
    assert acquire_ntfs.parse_boot_sector(raw).cluster_size == 128 * 1024
    with pytest.raises(AcquisitionError):
        acquire_ntfs.parse_boot_sector(bytes(512))


def test_fixups_restore_sector_tails_and_detect_torn_records():
    raw = bytearray(mft_record(5, file_name(".", 5)))
    assert raw[510:512] == b"\x07\x07"
    assert acquire_ntfs.apply_fixups(raw)
    torn = bytearray(mft_record(5, file_name(".", 5)))
    torn[1022] = 0
    assert not acquire_ntfs.apply_fixups(torn)


# --- reading the synthetic volume -----------------------------------------------------


def test_fragmented_mft_is_followed_through_its_attribute_list():
    image = build_volume()
    volume = acquire_ntfs.NtfsVolume(io.BytesIO(image))
    assert volume.mft.runs == [(8, 8), (32, 8)]
    out = io.BytesIO()
    volume.copy_stream(volume.mft, out)
    assert out.getvalue() == _cluster(image, 8, 8) + _cluster(image, 32, 8)
    # Record 12 is only reachable through the second extent.
    assert acquire_ntfs.record_file_name(volume.read_record(12)) == ("$UsnJrnl", 11)


def test_volume_offset_within_a_disk_image():
    image = bytes(5 * 4096) + build_volume()
    volume = acquire_ntfs.NtfsVolume(io.BytesIO(image), base=5 * 4096)
    assert volume.mft.runs == [(8, 8), (32, 8)]


def test_sparse_journal_is_compacted_to_its_allocated_runs():
    image = build_volume()
    volume = acquire_ntfs.NtfsVolume(io.BytesIO(image))
    out = io.BytesIO()
    result = volume.copy_stream(volume.stream(12, "$J"), out, compact=True)
    tail = J_REAL_SIZE - 8 * CS
    assert out.getvalue() == _cluster(image, 60, 2) + _cluster(image, 70)[:tail]
    assert result["extents"] == [
        {"stream_offset": 4 * CS, "file_offset": 0, "length": 2 * CS},
        {"stream_offset": 8 * CS, "file_offset": 2 * CS, "length": tail},
    ]
    assert result["sparse_bytes_skipped"] == 6 * CS
    assert result["stream_size"] == J_REAL_SIZE


def test_full_copy_zero_fills_sparse_runs_and_uninitialized_tail():
    image = build_volume()
    volume = acquire_ntfs.NtfsVolume(io.BytesIO(image))
    out = io.BytesIO()
    volume.copy_stream(volume.stream(12, "$J"), out)
    assert len(out.getvalue()) == J_REAL_SIZE
    assert out.getvalue()[: 4 * CS] == bytes(4 * CS)
    out = io.BytesIO()
    volume.copy_stream(volume.stream(13), out)
    expected = _cluster(image, 80, 2) + bytes(PAGEFILE_REAL - PAGEFILE_INIT)
    assert out.getvalue() == expected


def test_compressed_streams_are_refused():
    volume = acquire_ntfs.NtfsVolume(io.BytesIO(build_volume()))
    stream = volume.stream(13)
    stream.flags = acquire_ntfs.FLAG_COMPRESSED
    with pytest.raises(AcquisitionError):
        volume.copy_stream(stream, io.BytesIO())


def test_find_records_skips_deleted_and_wrong_parent(tmp_path):
    image = build_volume()
    mft = tmp_path / "MFT"
    mft.write_bytes(_cluster(image, 8, 8) + _cluster(image, 32, 8))
    found = acquire_ntfs.find_records(
        mft, RECORD, {"$UsnJrnl": 11, "pagefile.sys": 5, "swapfile.sys": 5}
    )
    assert found == {"$UsnJrnl": 12, "pagefile.sys": 13}
    assert acquire_ntfs.find_records(mft, RECORD, {"$UsnJrnl": 5}) == {}


# --- acquisition flow -------------------------------------------------------------------


@pytest.fixture
def fake_device(tmp_path, monkeypatch):
    """Route every raw device path to the synthetic image; record VSS calls."""
    image_path = tmp_path / "volume.img"
    image_path.write_bytes(build_volume())
    calls = {"opened": [], "deleted": []}

    def open_device(path):
        calls["opened"].append(path)
        return image_path.open("rb")

    monkeypatch.setattr(acquire_ntfs, "_open_device", open_device)
    monkeypatch.setattr(
        acquire_ntfs, "_create_snapshot", lambda drive: ("{shadow-1}", r"\\?\GLOBALROOT\Snap1")
    )
    monkeypatch.setattr(acquire_ntfs, "_delete_snapshot", calls["deleted"].append)
    return calls


def test_acquire_volume_reads_metafiles_from_snapshot_and_pagefile_live(tmp_path, fake_device):
    meta = acquire_ntfs.acquire_volume("c:", tmp_path / "out")
    dest = tmp_path / "out" / "C"
    assert meta["metafile_source"] == "vss"
    assert fake_device["opened"] == [r"\\?\GLOBALROOT\Snap1", r"\\.\C:"]
    assert fake_device["deleted"] == ["{shadow-1}"]
    assert (dest / "MFT").stat().st_size == 16 * RECORD
    assert (dest / "UsnJrnl_J").stat().st_size == 2 * CS + J_REAL_SIZE - 8 * CS
    assert meta["usnjrnl"]["record"] == 12
    assert meta["residue_files"]["pagefile.sys"]["status"] == "ok"
    assert meta["residue_files"]["swapfile.sys"]["status"] == "missing"
    assert meta["residue_files"]["hiberfil.sys"]["status"] == "skipped"
    assert (dest / "ntfs_metadata.json").is_file()


def test_snapshot_failure_falls_back_to_the_live_volume(tmp_path, fake_device, monkeypatch):
    def refuse(drive):
        raise AcquisitionError("VSS service disabled")

    monkeypatch.setattr(acquire_ntfs, "_create_snapshot", refuse)
    meta = acquire_ntfs.acquire_volume("C:", tmp_path / "out")
    assert meta["metafile_source"] == "live"
    assert "VSS service disabled" in meta["vss_error"]
    assert fake_device["deleted"] == []
    assert (tmp_path / "out" / "C" / "MFT").is_file()


def test_pagefile_skipped_when_output_drive_lacks_space(tmp_path, fake_device, monkeypatch):
    usage = namedtuple("usage", "total used free")
    monkeypatch.setattr(acquire_ntfs.shutil, "disk_usage", lambda p: usage(1, 1, 10))
    meta = acquire_ntfs.acquire_volume("C:", tmp_path / "out")
    assert meta["residue_files"]["pagefile.sys"]["status"] == "skipped"
    assert not (tmp_path / "out" / "C" / "pagefile.sys").exists()


def test_skip_pagefile_and_include_hiberfil(tmp_path, fake_device):
    meta = acquire_ntfs.acquire_volume(
        "C:", tmp_path / "out", include_pagefile=False, include_hiberfil=True
    )
    files = meta["residue_files"]
    assert files["pagefile.sys"]["status"] == "skipped"
    assert files["hiberfil.sys"]["status"] == "missing"


def test_acquire_all_hashes_each_volume_and_isolates_failures(tmp_path, fake_device, monkeypatch):
    real_open = acquire_ntfs._open_device

    def open_device(path):
        if "E:" in path:
            raise AcquisitionError("Could not open \\\\.\\E:")
        return real_open(path)

    monkeypatch.setattr(acquire_ntfs, "_open_device", open_device)
    result = acquire_ntfs.acquire_all(["C:", "c", "E:"], tmp_path / "ntfs")
    assert result["status"] == "ok"
    assert set(result["volumes"]) == {"C", "E"}
    assert result["volumes"]["E"]["status"] == "error"
    verification = verify_hashes(tmp_path / "ntfs" / "C")
    assert {v["status"] for v in verification.values()} == {"match"}
    assert {"MFT", "UsnJrnl_J", "pagefile.sys", "ntfs_metadata.json"} <= set(verification)
    assert Path(result["custody_log_path"]).is_file()


def test_acquire_all_reports_error_when_no_volume_exports(tmp_path, monkeypatch):
    def refuse(path):
        raise AcquisitionError("no device")

    monkeypatch.setattr(acquire_ntfs, "_open_device", refuse)
    monkeypatch.setattr(acquire_ntfs, "_create_snapshot", lambda d: ("{s}", "SNAP"))
    monkeypatch.setattr(acquire_ntfs, "_delete_snapshot", lambda s: None)
    result = acquire_ntfs.acquire_all(["C:"], tmp_path / "ntfs")
    assert result["status"] == "error"


def test_normalize_drive():
    assert acquire_ntfs.normalize_drive("d") == "D:"
    assert acquire_ntfs.normalize_drive(r"e:\Users\x\Tor Browser") == "E:"
    with pytest.raises(AcquisitionError):
        acquire_ntfs.normalize_drive(r"\\server\share\Tor Browser")


# --- acquire_all.py integration -------------------------------------------------------


def test_ntfs_volumes_are_system_drive_plus_tor_install_drives(monkeypatch):
    monkeypatch.setenv("SystemDrive", "C:")
    disk = {
        "tor_dir": {"status": "ok", "source_dir": r"D:\Tor Browser\Browser\TorBrowser\Data\Tor"},
        "profile": {"status": "ok", "source_dir": r"D:\Tor Browser\Browser\profile.default"},
        "other_installations_found": [r"\\nas\share\Tor Browser", r"F:\tb"],
    }
    assert acquire_all.ntfs_volumes(disk) == ["C:", "D:", "F:"]
    # A deleted install: the disk step failed, the system drive is still exported.
    assert acquire_all.ntfs_volumes({"status": "error", "message": "none found"}) == ["C:"]


def test_acquire_all_runs_ntfs_even_when_no_tor_install_is_found(tmp_path, monkeypatch):
    monkeypatch.setattr(acquire_all.sys, "platform", "win32")
    monkeypatch.setattr(acquire_all, "is_admin", lambda: True)
    monkeypatch.setattr(
        acquire_all, "_acquire_disk", lambda *a: {"status": "error", "message": "none found"}
    )
    seen = {}

    def fake_ntfs(drives, output_dir, include_pagefile, include_hiberfil):
        seen.update(drives=drives, pagefile=include_pagefile, hiberfil=include_hiberfil)
        return {"status": "ok", "path": str(output_dir), "volumes": {}}

    monkeypatch.setattr(acquire_all.acquire_ntfs, "acquire_all", fake_ntfs)
    monkeypatch.setenv("SystemDrive", "C:")
    manifest = acquire_all.acquire(
        tmp_path / "evidence",
        include_registry=False,
        include_memory=False,
        include_pagefile=False,
    )
    assert seen == {"drives": ["C:"], "pagefile": False, "hiberfil": False}
    assert manifest["disk"]["ntfs"]["path"] == "disk/ntfs"


def test_skip_ntfs(tmp_path, monkeypatch):
    monkeypatch.setattr(acquire_all.sys, "platform", "win32")
    monkeypatch.setattr(acquire_all, "is_admin", lambda: True)
    monkeypatch.setattr(acquire_all.acquire_ntfs, "acquire_all", lambda *a, **k: 1 / 0)
    manifest = acquire_all.acquire(
        tmp_path / "e",
        include_registry=False,
        include_memory=False,
        include_disk=False,
        include_ntfs=False,
    )
    assert "ntfs" not in manifest["disk"]


# --- analysis of the export -----------------------------------------------------------


def test_module_b_analyses_an_exported_volume(tmp_path, fake_device):
    ntfs_dir = tmp_path / "evidence" / "disk" / "ntfs"
    acquire_ntfs.acquire_all(["C:", "D:"], ntfs_dir)
    result = run_disk_module(TranceConfig("t", tmp_path / "out"), ntfs_dir=ntfs_dir)
    assert result.status == "ok", result.message
    ntfs = result.details["ntfs"]
    assert set(ntfs["volumes"]) == {"C", "D"}
    assert ntfs["volumes"]["C"]["metafile_source"] == "vss"
    assert ntfs["mft"]["records"] == 2 * 6  # six named base records per volume
    assert ntfs["usnjrnl"]["records"] == 4
    window = ntfs["usnjrnl"]["tor_activity_window"]
    assert window["events"] == 4
    assert window["last_utc"] == (T0 + dt.timedelta(minutes=5)).isoformat()
    assert {e["path"] for e in ntfs["usnjrnl"]["tor_events"]} == {"C:\\state", "D:\\state"}
    residue = result.details["memory_residue"]
    assert {f["path"] for f in residue["files"]} == {"C:\\pagefile.sys", "D:\\pagefile.sys"}
    assert residue["onion_addresses"][ONION + ".onion"]["occurrences"] == 2
    types = {a.artifact_type for a in result.artifacts}
    assert {"ntfs_tor_activity_window", "memory_residue_onion"} <= types


def test_module_b_rejects_a_tampered_export(tmp_path, fake_device):
    ntfs_dir = tmp_path / "ntfs"
    acquire_ntfs.acquire_all(["C:"], ntfs_dir)
    with (ntfs_dir / "C" / "MFT").open("r+b") as fh:
        fh.write(b"X")
    result = run_disk_module(TranceConfig("t", tmp_path / "out"), ntfs_dir=ntfs_dir)
    assert result.status == "error"
    assert "verification failed" in result.details["ntfs"]["error"]


def test_disk_root_takes_precedence_over_ntfs_export(tmp_path, fake_device):
    ntfs_dir = tmp_path / "ntfs"
    acquire_ntfs.acquire_all(["C:"], ntfs_dir)
    volume = tmp_path / "mounted"
    volume.mkdir()
    result = run_disk_module(
        TranceConfig("t", tmp_path / "out"), ntfs_dir=ntfs_dir, disk_root=volume
    )
    assert "show_sys_files" in result.details["ntfs"]["error"]


def test_resolve_evidence_finds_the_ntfs_export(tmp_path):
    (tmp_path / "disk" / "ntfs" / "C").mkdir(parents=True)
    (tmp_path / "disk" / "ntfs" / "C" / "MFT").write_bytes(b"")
    assert analyze_evidence.resolve_evidence(tmp_path)["ntfs_dir"] == str(
        tmp_path / "disk" / "ntfs"
    )
    manifest = {"disk": {"status": "error", "ntfs": {"status": "ok", "path": "disk/ntfs"}}}
    (tmp_path / "acquire_manifest.json").write_text(__import__("json").dumps(manifest))
    assert analyze_evidence.resolve_evidence(tmp_path)["ntfs_dir"] == str(
        tmp_path / "disk" / "ntfs"
    )


# --- a real NTFS volume (ntfs-3g's mkntfs/ntfscp/ntfscat) -------------------------------


@pytest.mark.skipif(
    not all(shutil.which(t) for t in ("mkntfs", "ntfscp", "ntfscat")),
    reason="ntfs-3g tools not installed",
)
def test_real_ntfs_volume_matches_ntfscat(tmp_path):
    image = tmp_path / "v.img"
    with image.open("wb") as fh:
        fh.truncate(32 << 20)
    subprocess.run(["mkntfs", "-F", "-Q", "-q", str(image)], check=True, capture_output=True)
    payload = hashlib.sha256(b"seed").digest() * 9000
    source = tmp_path / "pf"
    source.write_bytes(payload)
    subprocess.run(["ntfscp", "-q", str(image), str(source), "pagefile.sys"], check=True)
    for i in range(30):  # enough files to spread records past the first MFT cluster
        subprocess.run(["ntfscp", "-q", str(image), str(source), f"f{i}.bin"], check=True)
    reference = subprocess.run(
        ["ntfscat", str(image), "$MFT"], check=True, capture_output=True
    ).stdout

    with image.open("rb") as fh:
        volume = acquire_ntfs.NtfsVolume(fh)
        mft = tmp_path / "MFT"
        with mft.open("wb") as out:
            volume.copy_stream(volume.mft, out)
        found = acquire_ntfs.find_records(mft, volume.record_size, {"pagefile.sys": 5})
        out = io.BytesIO()
        volume.copy_stream(volume.stream(found["pagefile.sys"]), out)
    assert out.getvalue() == payload

    # ntfscat prints records with fixups applied; the export keeps on-disk bytes (what
    # analyze_ntfs_journal expects). They must agree once fixups are applied.
    raw = mft.read_bytes()
    fixed = bytearray()
    for i in range(0, len(raw), volume.record_size):
        record = bytearray(raw[i : i + volume.record_size])
        if record[:4] == b"FILE":
            assert acquire_ntfs.apply_fixups(record)
        fixed += record
    assert bytes(fixed) == reference
