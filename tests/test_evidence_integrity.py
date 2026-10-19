import hashlib
import json
import os

import pytest

import main
from core.config import TranceConfig
from core.evidence_integrity import evidence_inputs, verify_evidence


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _evidence(tmp_path):
    """A small acquire_all.py-shaped folder with every kind of hash record."""
    root = tmp_path / "evidence"
    (root / "registry").mkdir(parents=True)
    (root / "memory").mkdir()
    profile = root / "disk" / "profile"
    (profile / "bookmarkbackups").mkdir(parents=True)

    hive = root / "registry" / "SYSTEM_20261001T000000Z"
    hive.write_bytes(b"regf hive bytes")
    hive.with_name(hive.name + ".sha256").write_text(f"{_sha(hive.read_bytes())}  {hive.name}\n")
    dump = root / "memory" / "firefox_1_x.bin"
    dump.write_bytes(b"memory")
    dump.with_name(dump.name + ".sha256").write_text(f"{_sha(b'memory')}  {dump.name}\n")
    (profile / "places.sqlite").write_bytes(b"sqlite")
    (profile / "bookmarkbackups" / "b.jsonlz4").write_bytes(b"lz4")
    (profile / "hashes.sha256").write_text(
        f"{_sha(b'sqlite')}  places.sqlite\n{_sha(b'lz4')}  bookmarkbackups/b.jsonlz4\n"
    )
    manifest = root / "acquire_manifest.json"
    manifest.write_text(json.dumps({"registry": {}}))
    manifest.with_name(manifest.name + ".sha256").write_text(
        f"{_sha(manifest.read_bytes())}  {manifest.name}\n"
    )
    (root / "registry" / "registry_acquire_x.custody.json").write_text("[]")
    return root


def test_intact_folder_verifies(tmp_path):
    root = _evidence(tmp_path)
    result = verify_evidence(root)

    assert result["status"] == "verified"
    assert result["mismatched"] == [] and result["invalid"] == []
    assert set(result["verified"]) == {
        "registry/SYSTEM_20261001T000000Z",
        "memory/firefox_1_x.bin",
        "disk/profile/places.sqlite",
        "disk/profile/bookmarkbackups/b.jsonlz4",
        "acquire_manifest.json",
    }
    assert result["unhashed"] == []  # custody logs are metadata, not evidence


@pytest.mark.parametrize(
    "victim",
    [
        "registry/SYSTEM_20261001T000000Z",
        "disk/profile/bookmarkbackups/b.jsonlz4",
        "acquire_manifest.json",
    ],
)
def test_one_changed_byte_fails(tmp_path, victim):
    root = _evidence(tmp_path)
    path = root / victim
    path.write_bytes(path.read_bytes() + b"!")

    result = verify_evidence(root)

    assert result["status"] == "failed"
    assert [m["path"] for m in result["mismatched"]] == [victim]
    assert "FAILED" in result["message"]


def test_unsafe_record_paths_fail(tmp_path):
    root = _evidence(tmp_path)
    (root / "disk" / "profile" / "hashes.sha256").write_text(
        f"{_sha(b'x')}  ../../../outside\n{_sha(b'y')}  /etc/passwd\n{_sha(b'z')}  C:\\Windows\\x\n"
    )
    result = verify_evidence(root)

    assert result["status"] == "failed"
    assert len(result["invalid"]) == 3


def test_malformed_record_line_fails(tmp_path):
    root = _evidence(tmp_path)
    (root / "memory" / "firefox_1_x.bin.sha256").write_text("not a hash line\n")
    assert verify_evidence(root)["status"] == "failed"


def test_symlink_inside_evidence_fails(tmp_path):
    root = _evidence(tmp_path)
    secret = tmp_path / "examiner_secret.txt"
    secret.write_text("examiner data")
    try:
        os.symlink(secret, root / "disk" / "profile" / "cookies.sqlite")
    except (OSError, NotImplementedError):
        pytest.skip("cannot create symlinks here")
    result = verify_evidence(root)
    assert result["status"] == "failed"
    assert any("symbolic link" in i["reason"] for i in result["invalid"])


def test_missing_and_unhashed_files_warn_but_do_not_fail(tmp_path):
    root = _evidence(tmp_path)
    (root / "disk" / "profile" / "places.sqlite").unlink()
    (root / "memory" / "extra.bin").write_bytes(b"?")

    result = verify_evidence(root)

    assert result["status"] == "verified"
    assert [m["path"] for m in result["missing"]] == ["disk/profile/places.sqlite"]
    assert result["unhashed"] == ["memory/extra.bin"]
    assert "missing" in result["message"] and "not covered" in result["message"]


def test_folder_without_any_records_is_unverified(tmp_path):
    (tmp_path / "x.bin").write_bytes(b"x")
    assert verify_evidence(tmp_path)["status"] == "unverified"


def test_inputs_outside_the_folder_are_checked_by_their_own_sidecar(tmp_path):
    dump = tmp_path / "elsewhere" / "fullmem_x.raw"
    dump.parent.mkdir()
    dump.write_bytes(b"ram")
    dump.with_name(dump.name + ".sha256").write_text(f"{_sha(b'tampered')}  {dump.name}\n")

    result = verify_evidence(None, [dump])
    assert result["status"] == "failed"

    assert verify_evidence(None, [])["status"] == "not_applicable"


def test_evidence_inputs_skips_disk_image_and_mount():
    paths = evidence_inputs(
        {
            "module_a_registry": {"system": "s", "ntuser": None},
            "module_b_disk": {"profile_dir": "p", "disk_image": "img", "disk_root": "/mnt"},
            "module_c_memory": {"dump": "d", "onion": "x.onion"},
        }
    )
    assert [p.name for p in paths] == ["s", "p", "d"]


def test_pipeline_refuses_to_parse_tampered_evidence(tmp_path, monkeypatch):
    root = _evidence(tmp_path)
    hive = root / "registry" / "SYSTEM_20261001T000000Z"
    hive.write_bytes(b"evil hive")
    ran = []
    monkeypatch.setattr(main, "_run_modules", lambda *a, **k: ran.append(1) or [])

    config = TranceConfig(case_name="c", output_dir=tmp_path / "out" / "c", evidence_dir=root)
    pipeline = main.run_pipeline(
        config, {"module_a_registry": {"system": hive}, "module_b_disk": {}, "module_c_memory": {}}
    )

    assert ran == []  # no module was even started
    assert pipeline.has_error and pipeline.integrity_failed
    assert {r.status for r in pipeline.results} == {"error"}
    findings = json.loads(pipeline.findings_path.read_text())
    assert findings["evidence_integrity"]["status"] == "failed"
    assert (
        findings["evidence_integrity"]["mismatched"][0]["path"] == hive.relative_to(root).as_posix()
    )
    html = pipeline.report_path.read_text(encoding="utf-8")
    assert "Evidence integrity check failed" in html


def test_pipeline_records_a_clean_check(tmp_path):
    root = _evidence(tmp_path)
    config = TranceConfig(case_name="c", output_dir=tmp_path / "out" / "c", evidence_dir=root)
    pipeline = main.run_pipeline(
        config, {"module_a_registry": {}, "module_b_disk": {}, "module_c_memory": {}}
    )
    assert pipeline.integrity["status"] == "verified"
    assert not pipeline.integrity_failed
    findings = json.loads(pipeline.findings_path.read_text())
    assert findings["evidence_integrity"]["status"] == "verified"


def test_cli_exits_nonzero_on_tampered_evidence(tmp_path, capsys):
    root = _evidence(tmp_path)
    dump = root / "memory" / "firefox_1_x.bin"
    dump.write_bytes(b"changed")
    exit_code = main.main(
        [
            "--case",
            "c",
            "--output-dir",
            str(tmp_path / "out"),
            "--evidence-dir",
            str(root),
            "--dump",
            str(dump),
        ]
    )
    assert exit_code == 2
    assert "integrity check FAILED" in capsys.readouterr().err


def test_hash_check_reports_its_progress(tmp_path, capsys):
    from core.evidence_integrity import verify_evidence
    from core.hashing import hash_file

    image = tmp_path / "fullmem.raw"
    image.write_bytes(b"\x00" * 300_000)
    (tmp_path / "fullmem.raw.sha256").write_text(f"{hash_file(image)}  fullmem.raw\n")

    assert verify_evidence(tmp_path, [])["status"] == "verified"
    lines = [x for x in capsys.readouterr().err.splitlines() if "checking evidence hashes" in x]
    assert lines and lines[-1].startswith("progress: checking evidence hashes 100%")
