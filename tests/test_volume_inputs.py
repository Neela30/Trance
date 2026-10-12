"""Finding the registry hives, Tor Browser profile and tor data folder inside a mounted
Windows volume (a disk image analysed from the GUI), the powered-off case."""

import os
from pathlib import Path

from analyze_evidence import resolve_volume, with_volume_inputs


def _touch(path: Path, data: bytes = b"x") -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    return path


def _tor_install(base: Path, mtime: float | None = None) -> Path:
    torrc = _touch(base / "Browser" / "TorBrowser" / "Data" / "Tor" / "torrc")
    (base / "Browser" / "TorBrowser" / "Data" / "Browser" / "profile.default").mkdir(parents=True)
    if mtime is not None:
        os.utime(torrc, (mtime, mtime))
    return base


def _volume(root: Path, users=("Anonymous", "Other")) -> Path:
    _touch(root / "Windows" / "System32" / "config" / "SYSTEM")
    _touch(root / "Windows" / "System32" / "config" / "SOFTWARE")
    # Lower-case on a real disk; a volume mounted with ntfs-3g is case-sensitive.
    _touch(root / "Windows" / "appcompat" / "Programs" / "Amcache.hve")
    for user in users:
        _touch(root / "Users" / user / "NTUSER.DAT")
        _touch(
            root / "Users" / user / "AppData" / "Local" / "Microsoft" / "Windows" / "UsrClass.dat"
        )
    _touch(root / "Users" / "Default" / "NTUSER.DAT")
    (root / "Users" / "Public").mkdir(parents=True)
    return root


def test_finds_every_input_and_uses_the_tor_users_hives(tmp_path):
    root = _volume(tmp_path / "vol")
    install = _tor_install(root / "Users" / "Anonymous" / "Desktop" / "Tor Browser")

    found = resolve_volume(str(root))

    assert found["system"].endswith("config/SYSTEM")
    assert found["software"].endswith("config/SOFTWARE")
    assert found["amcache"].endswith("appcompat/Programs/Amcache.hve")
    assert found["ntuser"] == str(root / "Users" / "Anonymous" / "NTUSER.DAT")
    assert "Anonymous" in found["usrclass"] and found["usrclass"].endswith("UsrClass.dat")
    assert found["disk_profile"].endswith("Data/Browser/profile.default")
    assert found["tor_dir"] == str(install / "Browser" / "TorBrowser" / "Data" / "Tor")
    assert any("Anonymous" in n for n in found["volume_notes"])


def test_tor_outside_users_with_one_person_uses_that_person(tmp_path):
    root = _volume(tmp_path / "vol", users=("Anonymous",))
    _tor_install(root / "Tools" / "Tor Browser")
    found = resolve_volume(str(root))
    assert found["ntuser"] == str(root / "Users" / "Anonymous" / "NTUSER.DAT")
    assert "tor_dir" in found


def test_no_tor_and_several_people_chooses_no_user_hive(tmp_path):
    root = _volume(tmp_path / "vol", users=("Alice", "Bob"))
    found = resolve_volume(str(root))
    assert "ntuser" not in found and "usrclass" not in found
    assert "disk_profile" not in found
    assert found["system"]  # machine-wide hives are still found
    assert any("Several user profiles" in n for n in found["volume_notes"])


def test_several_installs_use_the_most_recently_active_one(tmp_path):
    root = _volume(tmp_path / "vol")
    _tor_install(root / "Users" / "Other" / "Desktop" / "Tor Browser", mtime=1_000_000)
    newer = _tor_install(root / "Users" / "Anonymous" / "Desktop" / "Tor Browser", mtime=2_000_000)
    found = resolve_volume(str(root))
    assert found["tor_dir"].startswith(str(newer))
    assert found["ntuser"] == str(root / "Users" / "Anonymous" / "NTUSER.DAT")
    assert any("More Tor Browser installs" in n for n in found["volume_notes"])


def test_not_a_folder_gives_nothing(tmp_path):
    assert resolve_volume(str(tmp_path / "missing")) == {}


def test_an_evidence_folders_copy_wins_and_the_cache_is_not_mutated(tmp_path):
    root = _volume(tmp_path / "vol")
    _tor_install(root / "Users" / "Anonymous" / "Desktop" / "Tor Browser")
    merged = with_volume_inputs({"system": "/evidence/registry/SYSTEM_x"}, root)
    assert merged["system"] == "/evidence/registry/SYSTEM_x"  # the acquired copy is kept
    assert merged["ntuser"].endswith("Anonymous/NTUSER.DAT")  # the rest comes from the volume
    merged["volume_notes"].append("changed by a caller")
    merged["ntuser"] = "changed"
    again = with_volume_inputs({}, root)
    assert again["ntuser"].endswith("Anonymous/NTUSER.DAT")
    assert "changed by a caller" not in again["volume_notes"]


def test_without_a_mounted_volume_nothing_changes():
    resolved = {"dump": "/e/memory/fullmem.raw"}
    assert with_volume_inputs(resolved, None) == resolved


def test_gui_request_with_a_mounted_volume_feeds_module_a(tmp_path):
    from gui.analysis_request import AnalysisRequest, effective_inputs
    from gui.pipeline_inputs import module_kwargs_from_resolved

    root = _volume(tmp_path / "vol")
    _tor_install(root / "Users" / "Anonymous" / "Desktop" / "Tor Browser")
    request = AnalysisRequest(
        case_name="c1",
        output_dir=str(tmp_path / "out"),
        disk_root=str(root),
        overrides={"amcache": str(_touch(tmp_path / "chosen" / "Amcache.hve"))},
    )
    inputs = effective_inputs(request)
    kwargs = module_kwargs_from_resolved(inputs, "", "", "")
    a = kwargs["module_a_registry"]
    assert all(a[k] is not None for k in ("system", "software", "ntuser", "usrclass"))
    assert a["amcache"] == tmp_path / "chosen" / "Amcache.hve"  # the examiner's choice wins
    assert kwargs["module_b_disk"]["profile_dir"] is not None
    assert kwargs["module_b_disk"]["disk_root"] == root
