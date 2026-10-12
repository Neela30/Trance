import json
from pathlib import Path

from gui.analysis_request import (
    AnalysisRequest,
    effective_inputs,
    guess_source_type,
    validate,
)
from gui.pipeline_inputs import module_kwargs_from_resolved


def _request(tmp_path, **fields):
    return AnalysisRequest(case_name="c1", output_dir=str(tmp_path / "out"), **fields)


def _file(path: Path) -> str:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(b"x")
    return str(path)


def test_overrides_win_over_discovered_inputs(tmp_path):
    override = _file(tmp_path / "mnt" / "SYSTEM")
    request = _request(tmp_path, overrides={"system": override, "bogus": "ignored"})
    inputs = effective_inputs(request, {"system": "evidence/SYSTEM_1", "ntuser": "n"})
    assert inputs["system"] == override
    assert inputs["ntuser"] == "n"
    assert "bogus" not in inputs


def test_dump_override_guesses_source_type_and_explicit_choice_wins(tmp_path):
    request = _request(tmp_path, overrides={"dump": "/x/fullmem_1.raw"})
    assert effective_inputs(request, {"source_type": "process"})["source_type"] == "full-memory"
    request.source_type = "process"
    assert effective_inputs(request, {})["source_type"] == "process"
    assert guess_source_type("firefox_4448_x.bin") == "process"
    assert guess_source_type("vm.elf") == "full-memory"


def test_disk_image_reaches_module_b_only_when_carving(tmp_path):
    image = _file(tmp_path / "disk.vdi")
    mount_only = effective_inputs(_request(tmp_path, disk_image=image, mount_image=True), {})
    assert "disk_image" not in mount_only
    carve = effective_inputs(_request(tmp_path, disk_image=image, carve_image=True), {})
    kwargs = module_kwargs_from_resolved(carve, "", "", "")
    assert kwargs["module_b_disk"]["disk_image"] == Path(image)


def test_every_cli_only_option_reaches_module_kwargs(tmp_path):
    request = _request(
        tmp_path,
        disk_root="/mnt/win10",
        vol3_path="vol",
        vol3_extract_process="firefox.exe",
        vol3_extract_pid=7912,
        source_type="full-memory",
    )
    kwargs = module_kwargs_from_resolved(effective_inputs(request, {}), "a.onion", "", "")
    assert kwargs["module_b_disk"]["disk_root"] == Path("/mnt/win10")
    memory = kwargs["module_c_memory"]
    assert memory["vol3_path"] == "vol"
    assert memory["vol3_extract_process"] == "firefox.exe"
    assert memory["vol3_extract_pid"] == 7912
    assert memory["source_type"] == "full-memory"


def test_request_round_trips_through_json(tmp_path):
    request = _request(tmp_path, overrides={"tor_dir": "/t"}, vol3_extract_pid=5, mount_image=True)
    assert AnalysisRequest.from_json(request.to_json()) == request
    assert json.loads(request.to_json())["case_name"] == "c1"


def test_validate_mirrors_main_py_case_name_and_existing_output_rules(tmp_path):
    dump = _file(tmp_path / "d.bin")
    for name in ("../x", "a/b", "a\\b", "..", ""):
        bad = AnalysisRequest(case_name=name, output_dir=str(tmp_path / "out"))
        assert any("single folder name" in e for e in validate(bad, {"dump": dump}).errors)

    request = _request(tmp_path)
    request.case_dir.mkdir(parents=True)
    (request.case_dir / "findings.json").write_text("{}")
    assert any("already has outputs" in e for e in validate(request, {"dump": dump}).errors)


def test_validate_requires_something_to_analyse_and_existing_paths(tmp_path):
    assert any("Nothing to analyse" in e for e in validate(_request(tmp_path), {}).errors)
    issues = validate(_request(tmp_path), {"tor_dir": str(tmp_path / "missing")})
    assert any("Tor data folder not found" in e for e in issues.errors)


def test_validate_disk_image_choices(tmp_path):
    image = _file(tmp_path / "disk.raw")
    neither = validate(_request(tmp_path, disk_image=image), {})
    assert any("tick 'Mount and analyse'" in e for e in neither.errors)
    both = validate(
        _request(tmp_path, disk_image=image, mount_image=True, disk_root=str(tmp_path)), {}
    )
    assert any("not both" in e for e in both.errors)
    assert not validate(_request(tmp_path, disk_image=image, mount_image=True), {}).errors


def test_validate_warns_when_a_mounted_volume_hides_system_files(tmp_path):
    root = tmp_path / "mnt"
    root.mkdir()
    issues = validate(_request(tmp_path, disk_root=str(root)), {})
    assert not issues.errors
    assert any("$MFT" in w for w in issues.warnings)
    (root / "$MFT").write_bytes(b"")
    assert not validate(_request(tmp_path, disk_root=str(root)), {}).warnings


def test_validate_rejects_output_inside_the_evidence(tmp_path):
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    request = AnalysisRequest(
        case_name="c1", output_dir=str(evidence / "out"), evidence_dir=str(evidence)
    )
    assert any("inside the evidence" in e for e in validate(request, {}).errors)


def test_validate_volatility_rules(tmp_path):
    dump = _file(tmp_path / "fullmem_1.raw")
    vol = _file(tmp_path / "vol")
    inputs = {"dump": dump, "source_type": "process"}
    no_vol = validate(_request(tmp_path, vol3_extract_process="firefox.exe"), inputs)
    assert any("needs the Volatility3" in e for e in no_vol.errors)
    assert any("full-memory image" in e for e in no_vol.errors)

    pid_only = validate(
        _request(tmp_path, vol3_path=vol, vol3_extract_pid=12),
        {"dump": dump, "source_type": "full-memory"},
    )
    assert any("needs the process name" in e for e in pid_only.errors)

    missing_vol = validate(_request(tmp_path, vol3_path=str(tmp_path / "nope")), inputs)
    assert any("not found" in e for e in missing_vol.errors)

    ok = validate(
        _request(tmp_path, vol3_path=vol, vol3_extract_process="firefox.exe", onion="a.onion"),
        {"dump": dump, "source_type": "full-memory"},
    )
    assert ok.errors == [] and ok.warnings == []


def test_validate_warns_when_memory_has_no_target(tmp_path):
    dump = _file(tmp_path / "d.bin")
    issues = validate(_request(tmp_path), {"dump": dump})
    assert issues.errors == []
    assert any("targeted URLs will be empty" in w for w in issues.warnings)


def test_validate_warns_that_a_full_memory_image_without_target_gives_observations_only(tmp_path):
    dump = _file(tmp_path / "d.raw")
    issues = validate(_request(tmp_path), {"dump": dump, "source_type": "full-memory"})
    assert issues.errors == []
    assert any("observations only" in w for w in issues.warnings)


def test_validate_accepts_a_blank_or_valid_report_timezone(tmp_path):
    dump = _file(tmp_path / "d.bin")
    inputs = {"dump": dump}
    assert validate(_request(tmp_path), inputs).errors == []
    # A real IANA zone must validate successfully -- if tzdata (requirements.txt) were
    # missing or not bundled by a PyInstaller build, ZoneInfo() would raise for every
    # zone name, including this one, and block Run for a perfectly valid timezone.
    valid = _request(tmp_path, report_timezone="Asia/Colombo")
    assert validate(valid, inputs).errors == []


def test_validate_rejects_an_unknown_report_timezone(tmp_path):
    dump = _file(tmp_path / "d.bin")
    bad = _request(tmp_path, report_timezone="Not/AZone")
    issues = validate(bad, {"dump": dump})
    assert any("Unknown timezone" in e for e in issues.errors)


def test_summary_includes_the_report_timezone_when_set(tmp_path):
    from gui.analysis_request import summary_rows

    request = _request(tmp_path, report_timezone="Asia/Colombo")
    rows = {row.label: row for row in summary_rows(request, {})}
    assert rows["Report timezone"].detail == "Asia/Colombo"
    assert "Report timezone" not in {row.label for row in summary_rows(_request(tmp_path), {})}


def test_summary_rows_describe_what_will_be_analysed(tmp_path):
    from gui.analysis_request import display_path, summary_rows

    evidence = tmp_path / "evidence"
    dump = _file(evidence / "memory" / "fullmem_1.raw")
    request = _request(tmp_path, evidence_dir=str(evidence))
    inputs = {"system": "s", "ntuser": "n", "dump": dump, "source_type": "full-memory"}
    rows = {row.label: row for row in summary_rows(request, inputs)}

    assert rows["Registry hives"].detail == "2 of 3 found"
    assert rows["Memory"].detail == "memory/fullmem_1.raw · full memory image"
    assert rows["Tor data folder"].state == "missing"
    assert rows["Disk image"].state == "off"
    assert display_path("/elsewhere/tor_dir", str(evidence)) == "tor_dir"

    image = _file(tmp_path / "vm.vdi")
    mounted = _request(tmp_path, disk_image=image, mount_image=True, carve_image=True)
    [disk] = [r for r in summary_rows(mounted, {}) if r.label == "Disk image"]
    assert disk.state == "found"
    assert disk.detail == "vm.vdi · mounted read-only + byte search"
