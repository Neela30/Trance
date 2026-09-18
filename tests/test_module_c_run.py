from core.config import TranceConfig
from modules import module_c_memory


def make_config(tmp_path):
    return TranceConfig(case_name="t", output_dir=tmp_path)


def make_dump(tmp_path, data: bytes):
    dump = tmp_path / "d.bin"
    dump.write_bytes(data)
    return dump


def test_run_skipped_without_dump(tmp_path):
    result = module_c_memory.run(make_config(tmp_path))
    assert result.status == "skipped"


def test_run_without_vol3_path_skips_process_extraction(tmp_path):
    dump = make_dump(tmp_path, b"http://target.onion/x\x00")
    result = module_c_memory.run(
        make_config(tmp_path), dump=dump, onion="target.onion", source_type="full-memory"
    )
    assert result.status == "ok"
    assert "process_extraction" not in result.details
    assert result.details["dump"]["source_type"] == "full-memory"


def test_run_extraction_failure_falls_back_to_full_image(tmp_path):
    dump = make_dump(tmp_path, b"http://target.onion/x\x00")
    result = module_c_memory.run(
        make_config(tmp_path),
        dump=dump,
        onion="target.onion",
        source_type="full-memory",
        vol3_path="definitely-not-a-real-vol-binary",
        vol3_extract_process="firefox.exe",
    )
    assert result.status == "ok"
    assert result.details["process_extraction"]["status"] == "error"
    # Fell back to analyzing the original full image, not a nonexistent extract.
    assert result.details["dump"]["path"] == str(dump)
    assert result.details["dump"]["source_type"] == "full-memory"
    assert len(result.details["targeted"]["urls"]) == 1


def test_run_extraction_success_narrows_analysis_to_extracted_dump(tmp_path, monkeypatch):
    from modules.module_c_memory import volatility_analyze

    dump = make_dump(tmp_path, b"NOISE user=UNRELATED\x00")
    extracted = tmp_path / "pid.4321.dmp"
    extracted.write_bytes(b"http://target.onion/login user=alice password=hunter2\x00")

    def fake_extract(vol_path, image_path, output_dir, process_name="firefox.exe", pid=None):
        return {
            "status": "ok",
            "message": None,
            "discovery": {"status": "ok", "chosen_pid": 4321, "chosen_reason": "test"},
            "source_image": str(image_path),
            "pid": 4321,
            "dump_path": str(extracted),
        }

    monkeypatch.setattr(volatility_analyze, "extract_target_process", fake_extract)

    result = module_c_memory.run(
        make_config(tmp_path),
        dump=dump,
        onion="target.onion",
        source_type="full-memory",
        vol3_path="vol",
        vol3_extract_process="firefox.exe",
    )
    assert result.status == "ok"
    assert result.details["process_extraction"]["status"] == "ok"
    assert result.details["process_extraction"]["pid"] == 4321
    # Analyzer ran against the extracted dump, not the original noisy full image.
    assert result.details["dump"]["path"] == str(extracted)
    assert result.details["dump"]["source_type"] == "process"
    credential_values = {c["value"] for c in result.details["targeted"]["credentials"]}
    assert {"alice", "hunter2"} <= credential_values
    assert "UNRELATED" not in credential_values


def test_run_extraction_not_triggered_for_process_source_type(tmp_path, monkeypatch):
    from modules.module_c_memory import volatility_analyze

    def fail_extract(*a, **k):
        raise AssertionError("extraction should not run for source_type='process'")

    monkeypatch.setattr(volatility_analyze, "extract_target_process", fail_extract)

    dump = make_dump(tmp_path, b"http://target.onion/x\x00")
    result = module_c_memory.run(
        make_config(tmp_path),
        dump=dump,
        onion="target.onion",
        source_type="process",
        vol3_path="vol",
        vol3_extract_process="firefox.exe",
    )
    assert result.status == "ok"
    assert "process_extraction" not in result.details
