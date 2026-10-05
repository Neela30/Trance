import datetime as dt
import struct

from core.config import TranceConfig
from modules.module_b_disk import correlate_downloads
from modules.module_b_disk import run as run_disk_module
from modules.module_b_disk.acquire_downloads import scan_live
from modules.module_b_disk.analyze_downloads import parse_recycle_index, recycle_bin_info
from modules.module_b_disk.report import build_context

DELETED = dt.datetime(2026, 10, 4, 20, 14, 5, tzinfo=dt.timezone.utc)
ZONE = b"[ZoneTransfer]\r\nZoneId=3\r\n"
SID = "S-1-5-21-1111-2222-3333-1001"


def _filetime(moment: dt.datetime) -> int:
    epoch = dt.datetime(1601, 1, 1, tzinfo=dt.timezone.utc)
    return int((moment - epoch).total_seconds() * 10_000_000)


def _index_v2(original: str, size: int = 1234) -> bytes:
    name = (original + "\x00").encode("utf-16-le")
    return struct.pack("<qqQI", 2, size, _filetime(DELETED), len(name) // 2) + name


def _index_v1(original: str, size: int = 99) -> bytes:
    name = original.encode("utf-16-le").ljust(520, b"\x00")
    return struct.pack("<qqQ", 1, size, _filetime(DELETED)) + name


def _recycle_bin(tmp_path):
    """A drive with one deleted download and one deleted folder holding a download."""
    drive = tmp_path / "C"
    bin_dir = drive / "$Recycle.Bin" / SID
    bin_dir.mkdir(parents=True)
    (bin_dir / "$RX7K2AB.zip").write_bytes(b"zip")
    (bin_dir / "$IX7K2AB.zip").write_bytes(_index_v2("C:\\Users\\a\\Downloads\\leak.zip"))
    folder = bin_dir / "$R9QW1ZZ"
    folder.mkdir()
    (folder / "notes.pdf").write_bytes(b"pdf")
    (bin_dir / "$I9QW1ZZ").write_bytes(_index_v2("C:\\Users\\a\\Desktop\\stuff"))
    (bin_dir / "desktop.ini").write_bytes(b"[.ShellClassInfo]")
    return drive, bin_dir


def test_parse_recycle_index_reads_both_formats():
    v2 = parse_recycle_index(_index_v2("C:\\x\\a.txt", 1234))
    assert v2 == {
        "original_path": "C:\\x\\a.txt",
        "original_size": 1234,
        "deleted_utc": DELETED.isoformat(),
        "index_version": 2,
    }
    v1 = parse_recycle_index(_index_v1("D:\\old\\b.bin"))
    assert v1["original_path"] == "D:\\old\\b.bin" and v1["index_version"] == 1
    assert parse_recycle_index(b"short") is None
    assert parse_recycle_index(struct.pack("<qqQ", 7, 0, 0)) is None


def test_recycle_bin_info_resolves_files_folders_and_missing_index(tmp_path):
    _drive, bin_dir = _recycle_bin(tmp_path)
    file_info = recycle_bin_info(bin_dir / "$RX7K2AB.zip")
    assert file_info["original_path"] == "C:\\Users\\a\\Downloads\\leak.zip"
    assert file_info["deleted_utc"] == DELETED.isoformat()
    assert file_info["sid"] == SID

    inside_folder = recycle_bin_info(bin_dir / "$R9QW1ZZ" / "notes.pdf")
    assert inside_folder["original_path"] == "C:\\Users\\a\\Desktop\\stuff\\notes.pdf"

    (bin_dir / "$RNOINDX.exe").write_bytes(b"x")
    orphan = recycle_bin_info(bin_dir / "$RNOINDX.exe")
    assert orphan["original_path"] is None and orphan["index_file"] == "$INOINDX.exe"

    assert recycle_bin_info(tmp_path / "C" / "Users" / "a" / "x.zip") is None


def test_live_scan_now_looks_inside_the_recycle_bin(tmp_path):
    drive, bin_dir = _recycle_bin(tmp_path)
    marked = {str(bin_dir / "$RX7K2AB.zip"), str(bin_dir / "$R9QW1ZZ" / "notes.pdf")}

    report = scan_live([drive], read_stream=lambda p, s: ZONE if p in marked else None)

    found = {h["recycle_bin"]["original_path"] for h in report["internet_origin_files"]}
    assert found == {
        "C:\\Users\\a\\Downloads\\leak.zip",
        "C:\\Users\\a\\Desktop\\stuff\\notes.pdf",
    }


def test_recycled_download_is_described_in_the_artifact_and_report(tmp_path):
    drive, bin_dir = _recycle_bin(tmp_path)
    marked = str(bin_dir / "$RX7K2AB.zip")
    scan = scan_live([drive], read_stream=lambda p, s: ZONE if p == marked else None)
    window = {
        "start_utc": "2026-10-04T20:00:00+00:00",
        "end_utc": "2026-10-04T21:00:00+00:00",
        "end_basis": "last daemon write",
    }
    correlate_downloads(scan, window)

    from modules.module_b_disk import _download_artifacts

    [artifact] = _download_artifacts(scan)
    assert (
        "in the Recycle Bin (originally C:\\Users\\a\\Downloads\\leak.zip" in artifact.description
    )
    assert "deleted 2026-10-04T20:14:05+00:00" in artifact.description

    context = build_context({"downloads": scan})["downloads"]
    assert context["recycled"] == 1
    assert context["hits"][0]["recycled"] == {
        "original_path": "C:\\Users\\a\\Downloads\\leak.zip",
        "deleted": "2026-10-04 20:14:05 UTC",
    }


def test_module_b_run_keeps_recycle_bin_details_from_a_live_scan(tmp_path):
    import json

    from tests.test_disk_evidence import manifest

    drive, bin_dir = _recycle_bin(tmp_path)
    marked = str(bin_dir / "$RX7K2AB.zip")
    scan = scan_live([drive], read_stream=lambda p, s: ZONE if p == marked else None)
    downloads = tmp_path / "evidence" / "disk" / "downloads"
    downloads.mkdir(parents=True)
    (downloads / "zone_identifier_scan.json").write_text(json.dumps(scan))
    manifest(downloads, ["zone_identifier_scan.json"])

    result = run_disk_module(
        TranceConfig("t", tmp_path / "out"),
        downloads_scan=downloads / "zone_identifier_scan.json",
    )
    [hit] = result.details["downloads"]["internet_origin_files"]
    assert hit["recycle_bin"]["original_path"] == "C:\\Users\\a\\Downloads\\leak.zip"


def test_mounted_volume_scan_also_annotates_recycle_bin_hits(tmp_path, monkeypatch):
    from modules.module_b_disk import analyze_downloads

    drive, bin_dir = _recycle_bin(tmp_path)
    marked = str(bin_dir / "$RX7K2AB.zip")
    monkeypatch.setattr(
        analyze_downloads, "_read_stream", lambda p, s: ZONE if p == marked else None
    )
    [hit] = analyze_downloads.scan_volume(drive)["internet_origin_files"]
    assert hit["path"] == f"$Recycle.Bin/{SID}/$RX7K2AB.zip"
    assert hit["recycle_bin"]["original_path"] == "C:\\Users\\a\\Downloads\\leak.zip"
