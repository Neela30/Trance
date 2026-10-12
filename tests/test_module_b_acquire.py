from pathlib import Path

import pytest

from core.exceptions import AcquisitionError
from modules.module_b_disk import acquire
from modules.module_b_disk.evidence import verify_hashes


def test_write_hash_manifest_is_readable_by_verify_hashes(tmp_path):
    (tmp_path / "places.sqlite").write_bytes(b"fake places db")
    (tmp_path / "cookies.sqlite").write_bytes(b"fake cookies db")

    acquire.write_hash_manifest(tmp_path)
    result = verify_hashes(tmp_path)

    assert result["places.sqlite"]["status"] == "match"
    assert result["cookies.sqlite"]["status"] == "match"


def test_copy_profile_skips_missing_files(tmp_path):
    src = tmp_path / "src"
    src.mkdir()
    (src / "places.sqlite").write_bytes(b"data")
    dest = tmp_path / "dest"

    result = acquire.copy_profile(src, dest)

    assert "places.sqlite" in result["copied"]
    assert "cookies.sqlite" in result["missing"]
    assert (dest / "places.sqlite").exists()
    assert not (dest / "cookies.sqlite").exists()


def test_copy_profile_includes_bookmark_backups(tmp_path):
    src = tmp_path / "src"
    (src / "bookmarkbackups").mkdir(parents=True)
    (src / "bookmarkbackups" / "backup1.jsonlz4").write_bytes(b"mozLz40\0fake")
    dest = tmp_path / "dest"

    result = acquire.copy_profile(src, dest)

    assert result["bookmark_backups_copied"] == ["backup1.jsonlz4"]
    assert (dest / "bookmarkbackups" / "backup1.jsonlz4").exists()


def test_copy_tor_datadir_includes_onion_auth(tmp_path):
    src = tmp_path / "src"
    (src / "onion-auth").mkdir(parents=True)
    (src / "onion-auth" / "example.auth_private").write_bytes(b"cred")
    (src / "state").write_bytes(b"state data")
    dest = tmp_path / "dest"

    result = acquire.copy_tor_datadir(src, dest)

    assert "state" in result["copied"]
    assert result["onion_auth_copied"] == ["example.auth_private"]


def test_discover_tor_browser_paths_requires_one_default_profile(tmp_path):
    root = tmp_path / "Tor Browser"
    data_browser = root / "Browser" / "TorBrowser" / "Data" / "Browser"
    tor_dir = root / "Browser" / "TorBrowser" / "Data" / "Tor"
    data_browser.mkdir(parents=True)
    tor_dir.mkdir(parents=True)

    with pytest.raises(AcquisitionError, match="No Tor Browser profile found"):
        acquire.discover_tor_browser_paths(root)

    (data_browser / "abc123.default").mkdir()
    profile, discovered_tor_dir = acquire.discover_tor_browser_paths(root)
    assert profile == data_browser / "abc123.default"
    assert discovered_tor_dir == tor_dir

    (data_browser / "xyz789.default").mkdir()
    with pytest.raises(AcquisitionError, match="Multiple candidate profiles"):
        acquire.discover_tor_browser_paths(root)


def test_discover_tor_browser_paths_requires_tor_dir(tmp_path):
    root = tmp_path / "Tor Browser"
    data_browser = root / "Browser" / "TorBrowser" / "Data" / "Browser"
    (data_browser / "abc123.default").mkdir(parents=True)

    with pytest.raises(AcquisitionError, match="Tor daemon data directory not found"):
        acquire.discover_tor_browser_paths(root)


def test_acquire_all_treats_an_empty_profile_source_as_all_missing_not_fatal(tmp_path):
    profile_src = tmp_path / "no-such-profile"  # doesn't exist at all
    tor_dir_src = tmp_path / "tor_dir"
    tor_dir_src.mkdir()
    (tor_dir_src / "state").write_bytes(b"state data")

    results = acquire.acquire_all(
        profile_src=profile_src, tor_dir_src=tor_dir_src, output_dir=tmp_path / "out"
    )

    assert results["profile"]["status"] == "ok"  # missing files are skipped, not fatal
    assert set(results["profile"]["missing"]) == set(acquire.PROFILE_FILENAMES)
    assert results["tor_dir"]["status"] == "ok"
    assert "state" in results["tor_dir"]["copied"]
    assert "custody_log_path" in results


def test_acquire_all_isolates_a_real_profile_failure_from_tor_dir(tmp_path):
    out_dir = tmp_path / "out"
    out_dir.mkdir()
    # Pre-create "profile" as a *file* so copy_profile's dest.mkdir() raises OSError.
    (out_dir / "profile").write_bytes(b"not a directory")

    tor_dir_src = tmp_path / "tor_dir"
    tor_dir_src.mkdir()
    (tor_dir_src / "state").write_bytes(b"state data")

    results = acquire.acquire_all(
        profile_src=tmp_path / "some-profile", tor_dir_src=tor_dir_src, output_dir=out_dir
    )

    assert results["profile"]["status"] == "error"
    assert results["tor_dir"]["status"] == "ok"


def _make_installation(root, marker_mtime=None):
    marker = root / acquire._TOR_MARKER
    marker.parent.mkdir(parents=True)
    marker.write_text("torrc contents")
    if marker_mtime is not None:
        import os

        os.utime(marker, (marker_mtime, marker_mtime))
    (root / "Browser" / "TorBrowser" / "Data" / "Browser" / "abc123.default").mkdir(parents=True)


def test_scan_for_marker_finds_a_real_installation(tmp_path):
    install_root = tmp_path / "Tor Browser"
    _make_installation(install_root)
    (tmp_path / "unrelated").mkdir()

    found = acquire._scan_for_marker(tmp_path)

    assert found == [install_root]


def test_scan_for_marker_does_not_descend_into_skip_listed_dirs(tmp_path):
    skipped = tmp_path / "System Volume Information"
    _make_installation(skipped)

    found = acquire._scan_for_marker(tmp_path)

    assert found == []


def test_scan_for_marker_respects_max_depth(tmp_path):
    deep_root = tmp_path
    for _ in range(10):
        deep_root = deep_root / "nested"
    _make_installation(deep_root)

    found = acquire._scan_for_marker(tmp_path, max_depth=3)

    assert found == []


def test_scan_for_marker_does_not_descend_into_a_found_install(tmp_path):
    install_root = tmp_path / "Tor Browser"
    _make_installation(install_root)
    # a second, nested marker inside the first install's tree must not also match --
    # the scan should stop descending the moment it finds one.
    _make_installation(install_root / "Browser" / "TorBrowser" / "nested-decoy")

    found = acquire._scan_for_marker(tmp_path)

    assert found == [install_root]


def test_find_tor_browser_installations_with_explicit_roots(tmp_path):
    install_a = tmp_path / "a"
    install_b = tmp_path / "b"
    _make_installation(install_a)
    _make_installation(install_b)

    found = acquire.find_tor_browser_installations(search_roots=[tmp_path])

    assert sorted(found) == sorted([install_a, install_b])


def testmost_recently_active_picks_the_newest_torrc(tmp_path):
    older = tmp_path / "older"
    newer = tmp_path / "newer"
    _make_installation(older, marker_mtime=1000)
    _make_installation(newer, marker_mtime=2000)

    assert acquire.most_recently_active([older, newer]) == newer


def test_acquire_all_auto_discovers_when_nothing_given(tmp_path, monkeypatch):
    install_root = tmp_path / "src" / "Tor Browser"
    _make_installation(install_root)
    (install_root / "Browser" / "TorBrowser" / "Data" / "Tor" / "state").write_text("x")

    monkeypatch.setattr(acquire, "find_tor_browser_installations", lambda: [install_root])

    results = acquire.acquire_all(output_dir=tmp_path / "out")

    assert results["profile"]["status"] == "ok"
    assert results["tor_dir"]["status"] == "ok"
    assert "other_installations_found" not in results


def test_acquire_all_logs_other_installations_but_uses_most_recent(tmp_path, monkeypatch, capsys):
    older = tmp_path / "older"
    newer = tmp_path / "newer"
    _make_installation(older, marker_mtime=1000)
    _make_installation(newer, marker_mtime=2000)

    monkeypatch.setattr(acquire, "find_tor_browser_installations", lambda: [older, newer])

    results = acquire.acquire_all(output_dir=tmp_path / "out")

    assert results["other_installations_found"] == [str(older)]
    assert "found 1 other Tor Browser install" in capsys.readouterr().out


def test_acquire_all_still_scans_downloads_when_auto_discovery_finds_nothing(tmp_path, monkeypatch):
    # A deleted install: no profile or tor_dir to copy, but the files it downloaded
    # are still on disk, so the downloads scan must run anyway.
    monkeypatch.setattr(acquire, "find_tor_browser_installations", list)
    scan_root = tmp_path / "drive"
    scan_root.mkdir()

    results = acquire.acquire_all(output_dir=tmp_path / "out", downloads_scan_roots=[scan_root])

    for step in ("profile", "tor_dir"):
        assert results[step]["status"] == "error"
        assert "No Tor Browser installation found" in results[step]["message"]
    assert results["downloads"]["status"] == "ok"
    assert Path(results["downloads"]["path"]).is_file()


def test_acquire_all_copies_an_explicit_tor_dir_even_if_discovery_fails(tmp_path, monkeypatch):
    monkeypatch.setattr(acquire, "find_tor_browser_installations", list)
    tor_dir = tmp_path / "tor"
    tor_dir.mkdir()
    (tor_dir / "state").write_text("TorVersion x\n")

    results = acquire.acquire_all(
        tor_dir_src=tor_dir, output_dir=tmp_path / "out", downloads_scan_roots=[tmp_path / "none"]
    )

    assert results["profile"]["status"] == "error"
    assert results["tor_dir"]["status"] == "ok"


def _real_shutil_copy2():
    import shutil

    return shutil.copy2


def test_copy_tor_datadir_skips_a_locked_file_and_keeps_its_metadata(tmp_path, monkeypatch):
    # tor.exe holds `lock` locked while running: reading it raises PermissionError on
    # Windows. That must not abort the rest of the copy (it used to: no hashes.sha256,
    # no custody entries, onion-auth never copied).
    src = tmp_path / "src"
    (src / "onion-auth").mkdir(parents=True)
    (src / "onion-auth" / "example.auth_private").write_bytes(b"cred")
    for name in ("state", "lock", "torrc"):
        (src / name).write_bytes(name.encode())
    real_copy2 = _real_shutil_copy2()

    def copy2(source, target, *args, **kwargs):
        if source.name == "lock":
            raise PermissionError(13, "Permission denied")
        return real_copy2(source, target, *args, **kwargs)

    monkeypatch.setattr(acquire.shutil, "copy2", copy2)
    result = acquire.copy_tor_datadir(src, tmp_path / "dest")

    assert set(result["copied"]) == {"state", "torrc"}
    assert "lock" in result["failed"]
    assert result["onion_auth_copied"] == ["example.auth_private"]
    assert result["metadata"]["lock"]["copied"] is False
    assert result["metadata"]["lock"]["modified_utc"]
    assert result["metadata"]["onion-auth/example.auth_private"]["copied"] is True


def test_acquire_tor_datadir_preserves_source_timestamps_for_analysis(tmp_path, monkeypatch):
    import json
    import os

    src = tmp_path / "src"
    src.mkdir()
    for name in ("state", "lock"):
        (src / name).write_bytes(name.encode())
    written = 1_788_000_000  # 2026-08-29, well before "now"
    os.utime(src / "lock", (written, written))
    monkeypatch.setattr(acquire, "tor_daemon_running", lambda _src: True)
    out = tmp_path / "out"
    out.mkdir()
    custody = acquire.CustodyLog(out / "c.json")

    result = acquire.acquire_tor_datadir(src, out, custody)

    metadata = json.loads((out / "tor_dir" / acquire.METADATA_FILENAME).read_text())
    assert metadata["tor_running_at_capture"] is True
    assert metadata["files"]["lock"]["modified_utc"].startswith("2026-08-29")
    assert result["tor_running_at_capture"] is True
    # The metadata file is covered by the hash manifest like every copied file.
    assert verify_hashes(out / "tor_dir")[acquire.METADATA_FILENAME]["status"] == "match"


def test_acquire_downloads_is_skipped_off_windows_without_explicit_roots(tmp_path, monkeypatch):
    monkeypatch.setattr(acquire.sys, "platform", "linux")
    custody = acquire.CustodyLog(tmp_path / "c.json")
    assert acquire.acquire_downloads(tmp_path, custody)["status"] == "skipped"


def test_scan_live_records_marked_files_and_skips_the_output_folder(tmp_path):
    from modules.module_b_disk.acquire_downloads import scan_live

    root = tmp_path / "drive"
    (root / "Users" / "a" / "Downloads").mkdir(parents=True)
    (root / "evidence").mkdir()
    marked = root / "Users" / "a" / "Downloads" / "tool.zip"
    unmarked = root / "Users" / "a" / "notes.txt"
    own_output = root / "evidence" / "fullmem.raw"
    for path in (marked, unmarked, own_output):
        path.write_bytes(path.name.encode())
    zone = b"[ZoneTransfer]\r\nZoneId=3\r\n"

    def read_stream(path, stream):
        return zone if path in (str(marked), str(own_output)) else None

    report = scan_live([root], exclude=[root / "evidence"], read_stream=read_stream)

    assert report["scan_method"] == "live_windows"
    assert report["files_walked"] == 2
    [hit] = report["internet_origin_files"]
    assert hit["path"] == str(marked)
    assert hit["zone_identifier"]["zone_id"] == 3
    assert hit["timestamps"]["modified_utc"]
    assert len(hit["sha256"]) == 64


def test_dumper_acquire_returns_the_dump_path(tmp_path, monkeypatch):
    # acquire_all records str(return value) in the manifest; it used to be None,
    # so every manifest said "path": "None" for a successful live dump.
    from modules.module_c_memory import dumper

    class FakeProc:
        pid = 4448

        def memory_info(self):
            return type("M", (), {"rss": 1024 * 1024})()

    def fake_dump(pid, output_path):
        output_path.write_bytes(b"memory")
        return 1, 6

    monkeypatch.setattr(dumper.sys, "platform", "win32")
    monkeypatch.setattr(dumper, "find_largest_firefox", FakeProc)
    monkeypatch.setattr(dumper, "dump_process_memory", fake_dump)

    path = dumper.acquire(tmp_path)

    assert path is not None and path.is_file()
    assert path.name.startswith("firefox_4448_")
