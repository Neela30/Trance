import datetime as dt
import hashlib
import json
import os
import sqlite3
import struct

import pytest

from core.config import TranceConfig
from core.exceptions import IntegrityError
from main import main as pipeline_main
from modules.module_b_disk import analyze_downloads, carve_onion_strings, daemon_window
from modules.module_b_disk import run as run_disk_module
from modules.module_b_disk.evidence import external_output, inventory, verify_hashes, working_copy
from modules.module_b_disk.recover_evidence import _open_ro, analyze_profile, main


def manifest(root, names):
    (root / "hashes.sha256").write_text(
        "".join(
            f"{hashlib.sha256((root / name).read_bytes()).hexdigest()}  ./{name}\n"
            for name in names
        )
    )


def test_nested_manifest_and_duplicate_basenames(tmp_path):
    for folder, content in [("a", b"one"), ("b", b"two")]:
        (tmp_path / folder).mkdir()
        (tmp_path / folder / "same file").write_bytes(content)
    manifest(tmp_path, ["a/same file", "b/same file"])
    result = verify_hashes(tmp_path)
    assert set(result) == {"a/same file", "b/same file"}
    assert all(v["status"] == "match" for v in result.values())


@pytest.mark.parametrize("name", ["db.sqlite", "db.sqlite-wal", "db.sqlite-shm"])
def test_all_mismatches_block_analysis(tmp_path, name):
    (tmp_path / name).write_bytes(b"original")
    manifest(tmp_path, [name])
    (tmp_path / name).write_bytes(b"changed")
    with pytest.raises(IntegrityError, match="Manifest verification failed"):
        analyze_profile(tmp_path)


@pytest.mark.parametrize(
    "entry",
    ["garbage", "0" * 64 + "  ../escape", "0" * 64 + "  /etc/passwd", "0" * 64 + "  missing"],
)
def test_invalid_and_missing_entries_block(tmp_path, entry):
    (tmp_path / "hashes.sha256").write_text(entry + "\n")
    with pytest.raises(IntegrityError):
        analyze_profile(tmp_path)


def test_symlink_rejected(tmp_path):
    source = tmp_path / "source"
    source.mkdir()
    (tmp_path / "external").write_text("outside")
    (source / "link").symlink_to(tmp_path / "external")
    with pytest.raises(IntegrityError, match="symbolic link"):
        analyze_profile(source)


def test_working_copy_detects_source_change(tmp_path):
    (tmp_path / "file").write_text("initial")
    with pytest.raises(IntegrityError, match="changed during analysis"), working_copy(tmp_path):
        (tmp_path / "file").write_text("changed")


def test_wal_only_record_and_source_preservation(tmp_path):
    db = tmp_path / "profile ?#.sqlite"
    writer = sqlite3.connect(db)
    try:
        writer.execute("PRAGMA journal_mode=WAL")
        writer.execute("PRAGMA wal_autocheckpoint=0")
        writer.execute("CREATE TABLE evidence(value TEXT)")
        writer.commit()
        writer.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        writer.execute("INSERT INTO evidence VALUES ('WAL-only record')")
        writer.commit()
        assert db.with_name(db.name + "-wal").stat().st_size > 0
        before = inventory(tmp_path)
        with _open_ro(db) as reader:
            assert reader.execute("SELECT value FROM evidence").fetchall() == [("WAL-only record",)]
        assert inventory(tmp_path) == before
        # Establish that the inserted row was not in the main database alone.
        main_only = tmp_path / "main-only.sqlite"
        main_only.write_bytes(db.read_bytes())
        with _open_ro(main_only) as reader:
            assert reader.execute("SELECT value FROM evidence").fetchall() == []
    finally:
        writer.close()


def test_output_guards_and_incomplete_reporting(tmp_path, capsys):
    source = tmp_path / "source"
    source.mkdir()
    (source / "places.sqlite").write_bytes(b"corrupt database")
    before = inventory(source)
    assert main([str(source), "--out", str(source / "report.json")]) == 1
    output = tmp_path / "results" / "report.json"
    assert main([str(source), "--out", str(output)]) == 2
    report = json.loads(output.read_text())
    assert report["analysis_status"] == "incomplete"
    assert report["integrity"]["manifest_status"] == "absent"
    assert report["integrity"]["source_unchanged"] is True
    assert "error" in report["places"]
    assert inventory(source) == before
    custody = json.loads(output.with_name("report.custody.json").read_text())
    assert custody[0]["artifact_path"] == str(source / "places.sqlite")
    contents = output.read_bytes()
    assert main([str(source), "--out", str(output)]) == 1
    assert output.read_bytes() == contents
    assert "Analysis incomplete" in capsys.readouterr().out


def test_output_symlink_into_evidence_rejected(tmp_path):
    source = tmp_path / "source"
    source.mkdir()
    alias = tmp_path / "alias"
    alias.symlink_to(source, target_is_directory=True)
    with pytest.raises(ValueError, match="outside"):
        external_output(alias / "report.json", source)


def _create_profile(profile):
    profile.mkdir()
    db = sqlite3.connect(profile / "places.sqlite")
    db.executescript("""
        CREATE TABLE moz_places(
            id INTEGER, url TEXT, title TEXT, visit_count INTEGER,
            hidden INTEGER, typed INTEGER, last_visit_date INTEGER
        );
        CREATE TABLE moz_historyvisits(id INTEGER);
        CREATE TABLE moz_inputhistory(id INTEGER);
        CREATE TABLE moz_anno_attributes(id INTEGER, name TEXT);
        CREATE TABLE moz_annos(
            id INTEGER, place_id INTEGER, anno_attribute_id INTEGER,
            content TEXT, dateAdded INTEGER, lastModified INTEGER
        );
        CREATE TABLE moz_keywords(id INTEGER);
        INSERT INTO moz_places VALUES (
            1, 'http://exampleexample.onion/page', 'Test', 1, 0, 1, 123456
        );
        INSERT INTO moz_anno_attributes VALUES (1, 'downloads/destinationFileURI');
        INSERT INTO moz_annos VALUES (
            1, 1, 1, 'file:///C:/Users/Anonymous/Downloads/secret.txt', 123456, 123456
        );
    """)
    db.close()
    db = sqlite3.connect(profile / "cookies.sqlite")
    db.executescript("""
        CREATE TABLE moz_cookies(
            host TEXT, name TEXT, creationTime INTEGER, lastAccessed INTEGER, expiry INTEGER
        );
        INSERT INTO moz_cookies VALUES ('exampleexample.onion', 'session', 1, 2, 3);
    """)
    db.close()
    db = sqlite3.connect(profile / "favicons.sqlite")
    db.executescript("""
        CREATE TABLE moz_pages_w_icons(page_url TEXT);
        INSERT INTO moz_pages_w_icons VALUES ('http://exampleexample.onion/page');
    """)
    db.close()


def _create_tor_dir(tor_dir):
    tor_dir.mkdir()
    (tor_dir / "state").write_text(
        """# Tor state file last generated on 2026-09-02 20:00:00 local time
TorVersion Tor 0.4.9.11
LastWritten 2026-09-02 20:00:00
TotalBuildTimes 2
CircuitBuildTimeBin 500 2
Guard nickname=TestGuard rsa_id=ABC confirmed_on=2026-09-02T19:00:00 pb_use_attempts=1 pb_use_successes=1 pb_circ_attempts=2 pb_circ_successes=2
"""
    )
    (tor_dir / "cached-microdesc-consensus").write_text("""network-status-version 3 microdesc
valid-after 2026-09-02 19:00:00
fresh-until 2026-09-02 20:00:00
valid-until 2026-09-02 22:00:00
""")
    (tor_dir / "lock").write_text("")
    auth = tor_dir / "onion-auth"
    auth.mkdir()
    address = "a" * 56
    key = "B" * 52
    (auth / f"{address}.auth_private").write_text(f"{address}:descriptor:x25519:{key}\n")


def test_daemon_uses_preserved_filesystem_metadata(tmp_path):
    tor_dir = tmp_path / "tor"
    _create_tor_dir(tor_dir)
    address = "a" * 56
    (tor_dir / "filesystem_metadata.json").write_text(
        json.dumps(
            {
                "source_image": "/evidence/disk.vdi",
                "partition_offset_sectors": 104448,
                "files": {
                    "cached-microdesc-consensus": {
                        "inode": "506-128-4",
                        "modified_utc": "2026-09-02T23:51:25+00:00",
                    },
                    "lock": {"inode": "114406-128-4", "modified_utc": "2026-09-02T23:51:11+00:00"},
                    f"onion-auth/{address}.auth_private": {
                        "inode": "513-128-1",
                        "modified_utc": "2026-09-02T23:52:42+00:00",
                    },
                },
            }
        )
    )
    result = run_disk_module(TranceConfig("test", tmp_path / "output"), tor_dir=tor_dir)
    daemon = result.details["tor_daemon"]
    credential = daemon["onion_auth"]["credentials"][0]
    assert daemon["hash_verification"] == {}
    assert daemon["consensus"]["file_mtime_utc"] == "2026-09-02T23:51:25+00:00"
    assert daemon["daemon_start_utc"] == "2026-09-02T23:51:11+00:00"
    assert credential["inode"] == "513-128-1"
    assert credential["mtime_utc"] == "2026-09-02T23:52:42+00:00"


def test_module_b_orchestrates_profile_and_daemon(tmp_path):
    profile = tmp_path / "profile"
    tor_dir = tmp_path / "tor"
    _create_profile(profile)
    _create_tor_dir(tor_dir)
    config = TranceConfig("test", tmp_path / "output")
    result = run_disk_module(config, profile_dir=profile, tor_dir=tor_dir)
    assert result.status == "ok"
    assert set(result.details) == {"profile", "tor_daemon"}
    assert result.details["profile"]["integrity"]["source_unchanged"] is True
    assert result.details["tor_daemon"]["integrity"]["source_unchanged"] is True
    types = {artifact.artifact_type for artifact in result.artifacts}
    assert types == {
        "browser_history",
        "browser_download",
        "browser_cookie",
        "favicon_page",
        "tor_guard_usage",
        "tor_consensus",
        "onion_client_auth_configuration",
    }
    auth_artifact = next(
        a for a in result.artifacts if a.artifact_type == "onion_client_auth_configuration"
    )
    assert "does not prove a visit" in auth_artifact.description
    assert "B" * 52 not in auth_artifact.description
    download_artifact = next(a for a in result.artifacts if a.artifact_type == "browser_download")
    assert "exampleexample.onion/page" in download_artifact.description
    assert "Downloads/secret.txt" in download_artifact.description
    downloads = result.details["profile"]["places"]["downloads"]
    assert downloads == [
        {
            "place_id": 1,
            "source_url": "http://exampleexample.onion/page",
            "destination_file_uri": "file:///C:/Users/Anonymous/Downloads/secret.txt",
            "date_added": 123456,
            "last_modified": 123456,
        }
    ]


def test_module_b_skips_without_input(tmp_path):
    result = run_disk_module(TranceConfig("test", tmp_path))
    assert result.status == "skipped"


def test_main_runs_module_b_and_refuses_case_overwrite(tmp_path):
    profile = tmp_path / "profile"
    tor_dir = tmp_path / "tor"
    output = tmp_path / "output"
    _create_profile(profile)
    _create_tor_dir(tor_dir)
    arguments = [
        "--case",
        "disk-case",
        "--output-dir",
        str(output),
        "--disk-profile",
        str(profile),
        "--tor-dir",
        str(tor_dir),
    ]
    assert pipeline_main(arguments) == 0
    findings = json.loads((output / "disk-case" / "findings.json").read_text())
    assert findings["modules"]["module_b_disk"]["status"] == "ok"
    assert findings["modules"]["module_b_disk"]["artifact_count"] == 7
    assert (output / "disk-case" / "report.html").is_file()
    with pytest.raises(SystemExit) as error:
        pipeline_main(arguments)
    assert error.value.code == 2


def test_main_refuses_output_inside_evidence(tmp_path):
    profile = tmp_path / "profile"
    _create_profile(profile)
    with pytest.raises(SystemExit) as error:
        pipeline_main(
            [
                "--case",
                "bad",
                "--output-dir",
                str(profile),
                "--disk-profile",
                str(profile),
            ]
        )
    assert error.value.code == 2


@pytest.mark.parametrize("case", ["../escape", "/tmp/escape", r"..\escape", ".", ".."])
def test_main_rejects_case_paths(tmp_path, case):
    with pytest.raises(SystemExit) as error:
        pipeline_main(["--case", case, "--output-dir", str(tmp_path)])
    assert error.value.code == 2


def test_raw_carve_hashes_image_and_deduplicates_overlap(tmp_path, monkeypatch):
    address = b"a" * 56 + b".onion"
    image = tmp_path / "disk.raw"
    image.write_bytes(b"x" * 10 + address + b"y" * 28 + address + b"z" * 100)
    monkeypatch.setattr(carve_onion_strings, "CHUNK", 80)
    monkeypatch.setattr(carve_onion_strings, "OVERLAP", 70)
    report = carve_onion_strings.scan(image, [])
    finding = report["onion_addresses"][address.decode()]
    assert finding["occurrences"] == 2
    assert finding["first_offsets"] == [10, 100]
    assert report["image_sha256"] == hashlib.sha256(image.read_bytes()).hexdigest()


def _filetime(moment: dt.datetime) -> int:
    epoch = dt.datetime(1601, 1, 1, tzinfo=dt.timezone.utc)
    return int((moment - epoch).total_seconds() * 10_000_000)


def _ntfs_times(created: dt.datetime) -> bytes:
    later = created + dt.timedelta(seconds=1)
    return struct.pack("<4Q", _filetime(created), _filetime(later), _filetime(later), 0)


def _fake_xattrs(monkeypatch, streams: dict):
    def read(path, name):
        return streams.get((os.path.realpath(path), name))

    monkeypatch.setattr(analyze_downloads, "_read_xattr", read)


def test_zone_identifier_parsing():
    tor_style = analyze_downloads.parse_zone_identifier(b"[ZoneTransfer]\r\nZoneId=3\r\n")
    assert tor_style["zone_id"] == 3
    assert tor_style["host_url"] is None and tor_style["referrer_url"] is None
    other = analyze_downloads.parse_zone_identifier(
        b"[ZoneTransfer]\r\nZoneId=3\r\nReferrerUrl=http://x.onion/\r\nHostUrl=http://x.onion/f\r\n"
    )
    assert other["host_url"] == "http://x.onion/f"
    assert other["referrer_url"] == "http://x.onion/"
    assert analyze_downloads.parse_zone_identifier(b"garbage")["zone_id"] is None


def test_scan_volume_keeps_only_marked_files(tmp_path, monkeypatch):
    volume = tmp_path / "volume"
    (volume / "Users" / "x" / "Desktop").mkdir(parents=True)
    (volume / "Windows").mkdir()
    marked = volume / "Users" / "x" / "Desktop" / "loot.txt"
    marked.write_bytes(b"downloaded")
    (volume / "Windows" / "system.dll").write_bytes(b"local")
    (volume / "link").symlink_to(marked)
    created = dt.datetime(2026, 9, 19, 8, 14, 44, tzinfo=dt.timezone.utc)
    _fake_xattrs(
        monkeypatch,
        {
            (str(marked), "user.Zone.Identifier"): b"[ZoneTransfer]\r\nZoneId=3\r\n",
            (str(marked), "system.ntfs_times"): _ntfs_times(created),
        },
    )
    report = analyze_downloads.scan_volume(volume)
    assert report["files_walked"] == 2
    assert report["xattr_support"] is True
    [hit] = report["internet_origin_files"]
    assert hit["path"] == os.path.join("Users", "x", "Desktop", "loot.txt")
    assert hit["sha256"] == hashlib.sha256(b"downloaded").hexdigest()
    assert hit["zone_identifier"]["zone_id"] == 3
    assert hit["timestamps"]["source"] == "ntfs"
    assert hit["timestamps"]["created_utc"] == "2026-09-19T08:14:44+00:00"
    assert hit["timestamps"]["modified_utc"] == "2026-09-19T08:14:45+00:00"
    assert hit["timestamps"]["accessed_utc"] is None


def test_scan_volume_falls_back_to_stat_without_ntfs_times(tmp_path, monkeypatch):
    marked = tmp_path / "f.bin"
    marked.write_bytes(b"x")
    _fake_xattrs(
        monkeypatch, {(str(marked), "user.Zone.Identifier"): b"[ZoneTransfer]\r\nZoneId=3"}
    )
    [hit] = analyze_downloads.scan_volume(tmp_path)["internet_origin_files"]
    assert hit["timestamps"]["source"] == "stat"
    assert hit["timestamps"]["created_utc"] is None
    assert hit["timestamps"]["modified_utc"]


def test_daemon_window_uses_lock_and_newest_write():
    assert daemon_window({"daemon_start_utc": None, "file_mtimes_utc": {}, "state": {}}) is None
    window = daemon_window(
        {
            "daemon_start_utc": "2026-09-02T19:00:00+00:00",
            "file_mtimes_utc": {
                "lock": "2026-09-02T19:00:00+00:00",
                "state": "2026-09-02T20:30:00+00:00",
            },
            "state": {"last_written_utc": "2026-09-02 20:00:00"},
        }
    )
    assert window == {
        "start_utc": "2026-09-02T19:00:00+00:00",
        "end_utc": "2026-09-02T20:30:00+00:00",
    }


def test_module_b_correlates_downloads_with_daemon_window(tmp_path, monkeypatch):
    tor_dir = tmp_path / "tor"
    _create_tor_dir(tor_dir)
    start = dt.datetime(2026, 9, 2, 19, 0, tzinfo=dt.timezone.utc)
    end = dt.datetime(2026, 9, 2, 20, 30, tzinfo=dt.timezone.utc)
    for path in tor_dir.rglob("*"):
        os.utime(path, (start.timestamp(), start.timestamp()))
    os.utime(tor_dir / "state", (end.timestamp(), end.timestamp()))

    volume = tmp_path / "volume"
    volume.mkdir()
    inside, outside, local = volume / "a.txt", volume / "b.txt", volume / "c.txt"
    for path in (inside, outside, local):
        path.write_bytes(path.name.encode())
    zone = b"[ZoneTransfer]\r\nZoneId=3\r\n"
    _fake_xattrs(
        monkeypatch,
        {
            (str(inside), "user.Zone.Identifier"): zone,
            (str(inside), "system.ntfs_times"): _ntfs_times(start + dt.timedelta(minutes=45)),
            (str(outside), "user.Zone.Identifier"): zone,
            (str(outside), "system.ntfs_times"): _ntfs_times(end + dt.timedelta(days=1)),
        },
    )
    result = run_disk_module(
        TranceConfig("test", tmp_path / "out"), tor_dir=tor_dir, disk_root=volume
    )
    assert result.status == "ok"
    downloads = result.details["downloads"]
    assert downloads["tor_daemon_window"] == {
        "start_utc": start.isoformat(),
        "end_utc": end.isoformat(),
    }
    flags = {h["path"]: h["within_tor_daemon_window"] for h in downloads["internet_origin_files"]}
    assert flags == {"a.txt": True, "b.txt": False}
    files = {
        a.description.split(";")[0]: a
        for a in result.artifacts
        if a.artifact_type == "internet_origin_file"
    }
    assert "while the Tor daemon was running" in files["a.txt"].description
    assert "source URL not recoverable" in files["a.txt"].description
    assert "outside the last recorded Tor daemon window" in files["b.txt"].description
    assert files["a.txt"].sha256 == hashlib.sha256(b"a.txt").hexdigest()


def test_module_b_download_scan_without_daemon(tmp_path, monkeypatch):
    volume = tmp_path / "volume"
    volume.mkdir()
    marked = volume / "f.txt"
    marked.write_bytes(b"f")
    _fake_xattrs(
        monkeypatch, {(str(marked), "user.Zone.Identifier"): b"[ZoneTransfer]\r\nZoneId=3"}
    )
    result = run_disk_module(TranceConfig("test", tmp_path / "out"), disk_root=volume)
    assert result.status == "ok"
    [hit] = result.details["downloads"]["internet_origin_files"]
    assert hit["within_tor_daemon_window"] is None
    assert "no Tor daemon window available" in result.artifacts[0].description


def test_main_runs_download_scan_and_records_custody(tmp_path, monkeypatch):
    volume = tmp_path / "volume"
    volume.mkdir()
    marked = volume / "f.txt"
    marked.write_bytes(b"f")
    _fake_xattrs(
        monkeypatch, {(str(marked), "user.Zone.Identifier"): b"[ZoneTransfer]\r\nZoneId=3"}
    )
    output = tmp_path / "output"
    assert (
        pipeline_main(["--case", "dl", "--output-dir", str(output), "--disk-root", str(volume)])
        == 0
    )
    findings = json.loads((output / "dl" / "findings.json").read_text())
    assert findings["modules"]["module_b_disk"]["artifact_count"] == 1
    custody = json.loads((output / "dl" / "custody.json").read_text())
    entry = next(e for e in custody if e["action"] == "hashed_in_place")
    assert entry["artifact_path"] == str(marked.resolve())
    assert entry["sha256"] == hashlib.sha256(b"f").hexdigest()
    with pytest.raises(SystemExit):
        pipeline_main(["--case", "x", "--output-dir", str(volume), "--disk-root", str(volume)])
