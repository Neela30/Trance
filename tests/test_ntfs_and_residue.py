import datetime as dt
import struct

from core.config import TranceConfig
from modules.module_b_disk import analyze_memory_residue, analyze_ntfs_journal
from modules.module_b_disk import run as run_disk_module

ONION = "jnagl5n7q47bdox4zscwgfyxcqsliulrh34qnexorwjwpbn37avtcdqd"
AUTH = "xm3raaijein7aeuike2d53kodwwpx4uhc5fg2wromy547ohbphoriaid"
T0 = dt.datetime(2026, 9, 19, 8, 0, tzinfo=dt.timezone.utc)


def _filetime(moment):
    return int((moment - dt.datetime(1601, 1, 1, tzinfo=dt.timezone.utc)).total_seconds() * 1e7)


def _attr(attr_type, value, name=""):
    name_bytes = name.encode("utf-16-le")
    header = 24
    name_off = header
    value_off = header + len(name_bytes)
    value_off += (-value_off) % 8
    length = value_off + len(value)
    length += (-length) % 8
    out = bytearray(length)
    struct.pack_into("<IIBBHHH", out, 0, attr_type, length, 0, len(name), name_off, 0, 0)
    struct.pack_into("<IH", out, 16, len(value), value_off)
    out[name_off : name_off + len(name_bytes)] = name_bytes
    out[value_off : value_off + len(value)] = value
    return bytes(out)


def _file_name_attr(name, parent, created, size=0):
    body = bytearray(66)
    struct.pack_into("<Q", body, 0, parent | (1 << 48))
    struct.pack_into("<QQQQ", body, 8, created, created, created, created)
    struct.pack_into("<QQ", body, 40, size, size)
    body[64] = len(name)
    body[65] = 1
    return _attr(0x30, bytes(body) + name.encode("utf-16-le"))


def _std_info(created):
    return _attr(0x10, struct.pack("<QQQQ", created, created, created, created) + b"\x00" * 16)


def _mft_record(number, name, parent, in_use=True, is_dir=False, data=None, streams=None):
    created = _filetime(T0 + dt.timedelta(minutes=number))
    attrs = _std_info(created) + _file_name_attr(name, parent, created, len(data or b""))
    if data is not None:
        attrs += _attr(0x80, data)
    for sname, sdata in (streams or {}).items():
        attrs += _attr(0x80, sdata, sname)
    attrs += struct.pack("<I", 0xFFFFFFFF) + b"\x00" * 4
    rec = bytearray(1024)
    rec[0:4] = b"FILE"
    usa_offset, usa_count = 48, 3
    struct.pack_into("<HH", rec, 4, usa_offset, usa_count)
    flags = (0x01 if in_use else 0) | (0x02 if is_dir else 0)
    struct.pack_into("<HHHH", rec, 16, 1, 1, 56, flags)
    struct.pack_into("<I", rec, 44, number)
    rec[56 : 56 + len(attrs)] = attrs
    # Fixups: sector tails hold the USN; the USA stores the displaced bytes.
    struct.pack_into("<H", rec, usa_offset, 0x1234)
    for i in (1, 2):
        end = i * 512
        rec[usa_offset + i * 2 : usa_offset + i * 2 + 2] = rec[end - 2 : end]
        struct.pack_into("<H", rec, end - 2, 0x1234)
    return bytes(rec)


def _mft(tmp_path):
    records = {
        5: _mft_record(5, ".", 5, is_dir=True),
        64: _mft_record(64, "Users", 5, is_dir=True),
        65: _mft_record(65, "u", 64, is_dir=True),
        66: _mft_record(66, "Downloads", 65, is_dir=True),
        70: _mft_record(70, "Tor Browser", 65, is_dir=True),
        71: _mft_record(71, "onion-auth", 70, is_dir=True),
        80: _mft_record(80, f"{AUTH}.auth_private", 71, in_use=False),
        81: _mft_record(
            81,
            "gone.txt",
            66,
            in_use=False,
            streams={"Zone.Identifier": b"[ZoneTransfer]\r\nZoneId=3\r\n"},
        ),
        82: _mft_record(82, "notes.txt", 66, data=f"see http://{ONION}.onion/x".encode()),
        83: _mft_record(83, "state", 70, in_use=False),
    }
    blob = b"".join(records.get(i, b"\x00" * 1024) for i in range(90))
    path = tmp_path / "MFT"
    path.write_bytes(blob)
    return path


def _usn_record(usn, ref, parent, minute, reason, name):
    name_bytes = name.encode("utf-16-le")
    length = 60 + len(name_bytes)
    length += (-length) % 8
    out = bytearray(length)
    struct.pack_into("<IHH", out, 0, length, 2, 0)
    struct.pack_into(
        "<QQQQIIIIHH",
        out,
        8,
        ref,
        parent,
        usn,
        _filetime(T0 + dt.timedelta(minutes=minute)),
        reason,
        0,
        0,
        0x20,
        len(name_bytes),
        60,
    )
    out[60 : 60 + len(name_bytes)] = name_bytes
    return bytes(out)


def _usnjrnl(tmp_path):
    records = [
        _usn_record(1, 80, 71, 1, 0x100, f"{AUTH}.auth_private.tmp"),
        _usn_record(2, 80, 71, 1, 0x2000, f"{AUTH}.auth_private"),
        _usn_record(3, 83, 70, 2, 0x2 | 0x80000000, "state"),
        _usn_record(4, 81, 66, 3, 0x100, "gone.txt"),
        _usn_record(5, 81, 66, 3, 0x20, "gone.txt"),
        _usn_record(6, 99, 5, 4, 0x2, "unrelated.log"),
        _usn_record(7, 83, 70, 40, 0x200, "state"),
    ]
    blob = b"\x00" * 4096 + b"".join(records) + b"\x00" * 4096
    path = tmp_path / "J"
    path.write_bytes(blob)
    return path


def test_mft_parses_names_paths_streams_and_deleted_records(tmp_path):
    records = analyze_ntfs_journal.parse_mft(_mft(tmp_path))
    assert analyze_ntfs_journal.resolve_path(records, 81) == "Users\\u\\Downloads\\gone.txt"
    report = analyze_ntfs_journal.analyze_mft_records(records)
    assert report["in_use"] == 7
    [onion] = report["onion_filenames"]
    assert onion["onion_address"] == AUTH + ".onion"
    assert onion["deleted"] is True
    assert onion["path"] == f"Users\\u\\Tor Browser\\onion-auth\\{AUTH}.auth_private"
    [zone] = report["zone_identifier_streams"]
    assert zone["deleted"] is True and zone["zone_identifier"]["zone_id"] == 3
    [resident] = report["resident_onion_strings"]
    assert resident["onion_addresses"] == [ONION + ".onion"]
    deleted_names = {d["name"] for d in report["deleted_tor_files"]}
    assert deleted_names == {f"{AUTH}.auth_private", "state"}


def test_usn_journal_yields_addresses_and_window(tmp_path):
    records = analyze_ntfs_journal.parse_mft(_mft(tmp_path))
    report = analyze_ntfs_journal.analyze_usn(_usnjrnl(tmp_path), records)
    assert report["records"] == 7
    [onion] = report["onion_filenames"]
    assert onion["onion_address"] == AUTH + ".onion"
    assert onion["events"] == 2
    assert report["tor_activity_window"]["first_utc"] == (T0 + dt.timedelta(minutes=1)).isoformat()
    assert report["tor_activity_window"]["last_utc"] == (T0 + dt.timedelta(minutes=40)).isoformat()
    assert {e["name"] for e in report["tor_events"]} == {
        f"{AUTH}.auth_private.tmp",
        f"{AUTH}.auth_private",
        "state",
    }
    assert report["downloads"] == []


def test_analyze_ntfs_merges_sources_and_reports_missing(tmp_path):
    report = analyze_ntfs_journal.analyze_ntfs(mft=_mft(tmp_path), usnjrnl=_usnjrnl(tmp_path))
    assert report["onion_addresses"] == {
        AUTH
        + ".onion": {
            "sources": ["mft", "usnjrnl"],
            "deleted": True,
            "paths": [f"Users\\u\\Tor Browser\\onion-auth\\{AUTH}.auth_private"],
        },
        ONION
        + ".onion": {
            "sources": ["mft_resident_data"],
            "deleted": False,
            "paths": ["Users\\u\\Downloads\\notes.txt"],
        },
    }
    empty = tmp_path / "empty"
    empty.mkdir()
    assert "show_sys_files" in analyze_ntfs_journal.analyze_ntfs(root=empty)["error"]


def test_memory_residue_finds_and_carves_candidates(tmp_path):
    (tmp_path / "Windows" / "Minidump").mkdir(parents=True)
    (tmp_path / "pagefile.sys").write_bytes(b"\x00" * 100 + f"http://{ONION}.onion/".encode() * 3)
    (tmp_path / "hiberfil.sys").write_bytes(b"hibr" + b"\x00" * 50)
    (tmp_path / "Windows" / "Minidump" / "a.dmp").write_bytes(
        f"{AUTH}:descriptor:x25519:{'B' * 52}".encode()
    )
    (tmp_path / "unrelated.bin").write_bytes(f"{ONION}.onion".encode())
    report = analyze_memory_residue.carve_residue(tmp_path)
    kinds = {f["kind"]: f for f in report["files"]}
    assert set(kinds) == {"pagefile", "hibernation", "minidump"}
    assert kinds["hibernation"]["compressed"] is True
    assert report["hibernation_present"] is True
    assert report["onion_addresses"] == {
        ONION + ".onion": {"occurrences": 3, "files": ["pagefile.sys"]}
    }
    assert kinds["minidump"]["client_auth_credentials"][0]["onion_address"] == AUTH + ".onion"


def test_module_b_runs_residue_and_ntfs_under_disk_root(tmp_path, monkeypatch):
    volume = tmp_path / "vol"
    (volume / "$Extend").mkdir(parents=True)
    (volume / "$MFT").write_bytes(_mft(tmp_path).read_bytes())
    (volume / "$Extend" / "$UsnJrnl:$J").write_bytes(_usnjrnl(tmp_path).read_bytes())
    (volume / "pagefile.sys").write_bytes(f"x{ONION}.onion".encode())
    monkeypatch.setattr(
        analyze_ntfs_journal,
        "locate",
        lambda root: (root / "$MFT", root / "$Extend" / "$UsnJrnl:$J"),
    )
    result = run_disk_module(TranceConfig("t", tmp_path / "out"), disk_root=volume)
    assert result.status == "ok", result.message
    types = {a.artifact_type for a in result.artifacts}
    assert {
        "memory_residue_onion",
        "ntfs_onion_address",
        "ntfs_deleted_download",
        "ntfs_tor_activity_window",
    } <= types
    deleted = next(a for a in result.artifacts if a.artifact_type == "ntfs_deleted_download")
    assert "gone.txt" in deleted.description
    auth = next(
        a
        for a in result.artifacts
        if a.artifact_type == "ntfs_onion_address" and AUTH in a.description
    )
    assert "since deleted" in auth.description


def test_module_b_tolerates_missing_metafiles(tmp_path):
    volume = tmp_path / "vol"
    volume.mkdir()
    result = run_disk_module(TranceConfig("t", tmp_path / "out"), disk_root=volume)
    assert result.status == "ok"
    assert "show_sys_files" in result.details["ntfs"]["error"]
    assert result.details["memory_residue"]["files"] == []


def test_usn_reconstructs_firefox_download_sequence(tmp_path):
    records = analyze_ntfs_journal.parse_mft(_mft(tmp_path))
    seq = [
        _usn_record(1, 90, 66, 10, 0x100, "x8KFRSgM.txt.part"),
        _usn_record(2, 90, 66, 10, 0x80000006, "x8KFRSgM.txt.part"),
        _usn_record(3, 90, 66, 11, 0x1000, "x8KFRSgM.txt.part"),
        _usn_record(4, 90, 66, 11, 0x2000, "report.txt"),
        _usn_record(5, 90, 66, 11, 0x00200020, "report.txt"),
        _usn_record(6, 90, 66, 12, 0x80000200, "report.txt"),
        _usn_record(7, 91, 66, 20, 0x1000, "setup.exe.crdownload"),
        _usn_record(8, 91, 66, 20, 0x2000, "setup.exe"),
        _usn_record(9, 92, 66, 30, 0x1000, "notes.part"),
        _usn_record(10, 92, 66, 30, 0x2000, "notes.txt"),
    ]
    path = tmp_path / "J2"
    path.write_bytes(b"".join(seq))
    report = analyze_ntfs_journal.analyze_usn(path, records)
    firefox, chromium = report["downloads"]
    assert firefox["path"] == "Users\\u\\Downloads\\report.txt"
    assert firefox["browser_family"] == "firefox"
    assert firefox["temp_name"] == "x8KFRSgM.txt.part"
    assert firefox["started_utc"] == (T0 + dt.timedelta(minutes=10)).isoformat()
    assert firefox["completed_utc"] == (T0 + dt.timedelta(minutes=11)).isoformat()
    assert firefox["zone_identifier_written_utc"] == (T0 + dt.timedelta(minutes=11)).isoformat()
    assert firefox["deleted_utc"] == (T0 + dt.timedelta(minutes=12)).isoformat()
    assert chromium["browser_family"] == "chromium" and chromium["started_utc"] is None
    # "notes.part" lacks Firefox's 8-random-character prefix, so it is not a download.


def test_onion_checksum_rejects_lookalike_filenames(tmp_path):
    from modules.module_b_disk.onion import is_v3_onion

    assert is_v3_onion(ONION) and is_v3_onion(AUTH + ".onion")
    assert not is_v3_onion("immersiveproductidentityherobackgroundroundedrectangleop")
    assert not is_v3_onion("a" * 56)
    records = {
        5: {
            "record": 5,
            "in_use": True,
            "name": ".",
            "parent": 5,
            "created_utc": None,
            "modified_utc": None,
            "fn_created_utc": None,
            "size": 0,
            "resident_data": None,
            "streams": {},
        },
        9: {
            "record": 9,
            "in_use": True,
            "name": "immersiveproductidentityherobackgroundroundedrectangleop.png",
            "parent": 5,
            "created_utc": None,
            "modified_utc": None,
            "fn_created_utc": None,
            "size": 0,
            "resident_data": b"see " + b"a" * 56 + b".onion",
            "streams": {},
        },
    }
    report = analyze_ntfs_journal.analyze_mft_records(records)
    assert report["onion_filenames"] == []
    assert report["resident_onion_strings"] == []
    residue = (
        analyze_memory_residue.carve_residue.__wrapped__
        if hasattr(analyze_memory_residue.carve_residue, "__wrapped__")
        else None
    )
    (tmp_path / "pagefile.sys").write_bytes(b"a" * 56 + b".onion " + ONION.encode() + b".onion")
    result = analyze_memory_residue.carve_residue(tmp_path)
    assert list(result["onion_addresses"]) == [ONION + ".onion"]
