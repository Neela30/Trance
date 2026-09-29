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


def test_acquire_all_requires_a_source(tmp_path):
    with pytest.raises(AcquisitionError, match="Pass --tor-browser-dir"):
        acquire.acquire_all(output_dir=tmp_path / "out")


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


def test_most_recently_active_picks_the_newest_torrc(tmp_path):
    older = tmp_path / "older"
    newer = tmp_path / "newer"
    _make_installation(older, marker_mtime=1000)
    _make_installation(newer, marker_mtime=2000)

    assert acquire._most_recently_active([older, newer]) == newer


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


def test_acquire_all_raises_when_auto_discovery_finds_nothing(tmp_path, monkeypatch):
    monkeypatch.setattr(acquire, "find_tor_browser_installations", list)

    with pytest.raises(AcquisitionError, match="No Tor Browser installation found"):
        acquire.acquire_all(output_dir=tmp_path / "out")
