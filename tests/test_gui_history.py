import json

from gui.history import scan_history


def _write_findings(case_dir, *, name, generated_at, modules):
    case_dir.mkdir(parents=True)
    findings = {
        "schema_version": 1,
        "case": {"name": name, "output_dir": str(case_dir), "evidence_dir": None},
        "generated_at": generated_at,
        "modules": modules,
        "artifacts": [],
    }
    (case_dir / "findings.json").write_text(json.dumps(findings))


def test_scan_history_empty_output_dir_returns_empty_list(tmp_path):
    assert scan_history(tmp_path / "does-not-exist") == []
    assert scan_history(tmp_path) == []


def test_scan_history_skips_case_dirs_without_findings_json(tmp_path):
    (tmp_path / "incomplete-run").mkdir()

    assert scan_history(tmp_path) == []


def test_scan_history_skips_corrupted_findings_json(tmp_path):
    case_dir = tmp_path / "corrupt"
    case_dir.mkdir()
    (case_dir / "findings.json").write_text("{not valid json")

    assert scan_history(tmp_path) == []


def test_scan_history_derives_overall_status_and_artifact_count(tmp_path):
    _write_findings(
        tmp_path / "c1",
        name="c1",
        generated_at="2026-09-01T00:00:00+00:00",
        modules={
            "module_a_registry": {"status": "ok", "artifact_count": 3},
            "module_b_disk": {"status": "skipped", "artifact_count": 0},
            "module_c_memory": {"status": "error", "artifact_count": 0},
        },
    )

    summaries = scan_history(tmp_path)

    assert len(summaries) == 1
    assert summaries[0].case_name == "c1"
    assert summaries[0].overall_status == "error"
    assert summaries[0].artifact_count == 3
    assert summaries[0].module_statuses["module_c_memory"] == "error"


def test_scan_history_sorts_most_recent_first(tmp_path):
    _write_findings(
        tmp_path / "older",
        name="older",
        generated_at="2026-09-01T00:00:00+00:00",
        modules={"module_a_registry": {"status": "ok", "artifact_count": 1}},
    )
    _write_findings(
        tmp_path / "newer",
        name="newer",
        generated_at="2026-09-20T00:00:00+00:00",
        modules={"module_a_registry": {"status": "ok", "artifact_count": 1}},
    )

    summaries = scan_history(tmp_path)

    assert [s.case_name for s in summaries] == ["newer", "older"]


def test_scan_history_report_and_custody_paths_only_set_when_files_exist(tmp_path):
    case_dir = tmp_path / "c1"
    _write_findings(
        case_dir,
        name="c1",
        generated_at="2026-09-01T00:00:00+00:00",
        modules={"module_a_registry": {"status": "ok", "artifact_count": 0}},
    )

    summaries = scan_history(tmp_path)
    assert summaries[0].report_path is None
    assert summaries[0].custody_path is None

    (case_dir / "report.html").write_text("<html></html>")
    (case_dir / "custody.json").write_text("[]")

    summaries = scan_history(tmp_path)
    assert summaries[0].report_path == case_dir / "report.html"
    assert summaries[0].custody_path == case_dir / "custody.json"
