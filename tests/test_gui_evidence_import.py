import hashlib
import json
import os
import stat
import sys
from datetime import datetime, timezone

import pytest

from gui.analysis_request import AnalysisRequest, validate
from gui.evidence_import import (
    IMPORT_DIRNAME,
    RECORD_NAME,
    EvidenceImportError,
    ImportCancelled,
    check_import,
    destination_for,
    import_evidence,
    store_root,
)

NOW = datetime(2026, 10, 13, 9, 30, 0, tzinfo=timezone.utc)


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _drive(tmp_path):
    """An acquire_all.py evidence folder on a 'removable drive'."""
    source = tmp_path / "usb" / "evidence"
    (source / "registry").mkdir(parents=True)
    (source / "disk" / "profile").mkdir(parents=True)
    hive = source / "registry" / "SYSTEM_x"
    hive.write_bytes(b"hive" * 1000)
    hive.with_name("SYSTEM_x.sha256").write_text(f"{_sha(hive.read_bytes())}  SYSTEM_x\n")
    (source / "disk" / "profile" / "places.sqlite").write_bytes(b"db")
    (source / "disk" / "profile" / "hashes.sha256").write_text(f"{_sha(b'db')}  places.sqlite\n")
    return source


def _snapshot(root):
    """Everything observable about a folder: names, bytes, modes, modification times."""
    state = {}
    for path in sorted(root.rglob("*")):
        info = path.stat()
        content = path.read_bytes() if path.is_file() else None
        state[path.relative_to(root).as_posix()] = (content, info.st_mode, info.st_mtime_ns)
    return state


def _store(tmp_path):
    return store_root(tmp_path / "output")


def test_import_copies_verifies_and_makes_read_only(tmp_path):
    source = _drive(tmp_path)
    result = import_evidence(source, _store(tmp_path), now=NOW)

    assert result.destination == _store(tmp_path) / "evidence_20261013T093000Z"
    assert result.evidence_dir == result.destination / "evidence"
    assert result.files_copied == 4
    assert result.integrity["status"] == "verified"
    assert not result.integrity_failed and result.safe_to_unplug
    copied = result.evidence_dir / "registry" / "SYSTEM_x"
    assert copied.read_bytes() == (source / "registry" / "SYSTEM_x").read_bytes()
    for path in result.destination.rglob("*"):
        if path.is_file():
            assert not path.stat().st_mode & stat.S_IWRITE
    with pytest.raises(PermissionError):
        copied.open("ab")
    record = json.loads((result.destination / RECORD_NAME).read_text())
    assert record["source"] == str(source)
    assert record["files"]["registry/SYSTEM_x"] == _sha(b"hive" * 1000)
    assert record["integrity"]["status"] == "verified"


def test_source_drive_is_never_modified(tmp_path):
    source = _drive(tmp_path)
    before = _snapshot(source.parent)

    import_evidence(source, _store(tmp_path), now=NOW)

    assert _snapshot(source.parent) == before


def test_copy_keeps_source_modification_times(tmp_path):
    source = _drive(tmp_path)
    hive = source / "registry" / "SYSTEM_x"
    os.utime(hive, ns=(1_600_000_000_000_000_000, 1_600_000_000_000_000_000))
    result = import_evidence(source, _store(tmp_path), now=NOW)
    copied = result.evidence_dir / "registry" / "SYSTEM_x"
    assert copied.stat().st_mtime_ns == 1_600_000_000_000_000_000


def test_tampered_evidence_is_imported_but_flagged(tmp_path):
    source = _drive(tmp_path)
    (source / "disk" / "profile" / "places.sqlite").write_bytes(b"changed")

    result = import_evidence(source, _store(tmp_path), now=NOW)

    assert result.integrity_failed
    assert result.integrity["mismatched"][0]["path"] == "disk/profile/places.sqlite"
    assert result.safe_to_unplug


def test_refuses_a_non_empty_destination(tmp_path):
    source = _drive(tmp_path)
    destination = destination_for(source, _store(tmp_path), NOW)
    destination.mkdir(parents=True)
    (destination / "other.txt").write_text("not ours")

    with pytest.raises(EvidenceImportError, match="not empty"):
        import_evidence(source, _store(tmp_path), now=NOW)
    assert (destination / "other.txt").read_text() == "not ours"
    assert [p.name for p in destination.iterdir()] == ["other.txt"]


def test_refuses_nesting(tmp_path):
    source = _drive(tmp_path)
    assert check_import(source, source / "copy")
    assert check_import(tmp_path / "store" / "x", tmp_path / "store")
    assert check_import(tmp_path / "missing", tmp_path / "dest")


def test_cancel_removes_the_partial_copy_only(tmp_path):
    source = _drive(tmp_path)
    store = _store(tmp_path)
    store.mkdir(parents=True)
    (store / "earlier_import").mkdir()
    calls = {"n": 0}

    def cancel_after_first_chunk():
        calls["n"] += 1
        return calls["n"] > 1

    with pytest.raises(ImportCancelled):
        import_evidence(source, store, should_cancel=cancel_after_first_chunk, now=NOW)
    assert [p.name for p in store.iterdir()] == ["earlier_import"]
    assert (source / "registry" / "SYSTEM_x").is_file()


def test_failed_copy_check_removes_the_partial_copy(tmp_path, monkeypatch):
    source = _drive(tmp_path)
    monkeypatch.setattr("gui.evidence_import._hash", lambda path: "0" * 64)

    with pytest.raises(EvidenceImportError, match="does not match"):
        import_evidence(source, _store(tmp_path), now=NOW)
    assert not destination_for(source, _store(tmp_path), NOW).exists()


def test_links_on_the_drive_are_not_followed(tmp_path):
    source = _drive(tmp_path)
    secret = tmp_path / "examiner_secret.txt"
    secret.write_text("examiner data")
    try:
        os.symlink(secret, source / "disk" / "profile" / "cookies.sqlite")
    except (OSError, NotImplementedError):
        pytest.skip("cannot create symlinks here")

    result = import_evidence(source, _store(tmp_path), now=NOW)

    assert not (result.evidence_dir / "disk" / "profile" / "cookies.sqlite").exists()
    assert any("cookies.sqlite" in s for s in result.skipped)


def test_progress_reports_bytes(tmp_path):
    source = _drive(tmp_path)
    seen = []
    import_evidence(source, _store(tmp_path), on_progress=lambda *a: seen.append(a), now=NOW)
    total = seen[0][2]
    assert seen[-1][1] == total and total > 4000


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX folder permissions")
def test_folders_are_read_only_too_on_posix(tmp_path):
    result = import_evidence(_drive(tmp_path), _store(tmp_path), now=NOW)
    with pytest.raises(PermissionError):
        (result.evidence_dir / "new_file").write_text("x")


def test_case_name_cannot_shadow_the_import_store(tmp_path):
    request = AnalysisRequest(case_name=IMPORT_DIRNAME, output_dir=str(tmp_path))
    assert any("imported evidence" in e for e in validate(request, {"dump": __file__}).errors)


def test_read_only_import_still_analyses_through_module_b_working_copy(tmp_path):
    """Module B copies the profile to a temp folder and opens sqlite there; that copy must be
    writable even though the imported evidence is read-only."""
    from modules.module_b_disk.evidence import working_copy

    result = import_evidence(_drive(tmp_path), _store(tmp_path), now=NOW)
    profile = result.evidence_dir / "disk" / "profile"
    with working_copy(profile) as (copy, _before, _verification):
        target = copy / "places.sqlite"
        with target.open("ab") as stream:
            stream.write(b"")
