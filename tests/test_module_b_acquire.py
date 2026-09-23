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
