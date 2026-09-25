import json

import main
from core.config import TranceConfig

_EMPTY_MODULE_KWARGS = {
    "module_a_registry": {},
    "module_b_disk": {},
    "module_c_memory": {},
}


def test_run_pipeline_matches_cli_main_for_the_same_inputs(tmp_path):
    cli_output = tmp_path / "cli"
    exit_code = main.main(["--case", "c1", "--output-dir", str(cli_output)])
    assert exit_code == 0

    config = TranceConfig(case_name="c1", output_dir=tmp_path / "direct" / "c1")
    config.output_dir.mkdir(parents=True)
    pipeline = main.run_pipeline(config, _EMPTY_MODULE_KWARGS)

    cli_findings = json.loads((cli_output / "c1" / "findings.json").read_text())
    direct_findings = json.loads(pipeline.findings_path.read_text())
    cli_findings["generated_at"] = direct_findings["generated_at"] = None
    cli_findings["case"]["output_dir"] = direct_findings["case"]["output_dir"] = None
    assert cli_findings == direct_findings


def test_run_pipeline_calls_progress_cb_once_per_module_plus_finalize(tmp_path):
    config = TranceConfig(case_name="c1", output_dir=tmp_path)
    calls = []

    main.run_pipeline(config, _EMPTY_MODULE_KWARGS, progress_cb=lambda *a: calls.append(a))

    assert [c[0] for c in calls] == [*main.MODULES, "finalize"]
    assert [c[1] for c in calls] == [1, 2, 3, 4]
    assert all(c[2] == 4 for c in calls)


def test_run_pipeline_has_error_reflects_module_errors(tmp_path):
    config = TranceConfig(case_name="c1", output_dir=tmp_path)
    pipeline = main.run_pipeline(config, _EMPTY_MODULE_KWARGS)
    assert pipeline.has_error is False  # every module skipped, not errored, with no evidence
