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

    # Modules run at the same time, so which reports first isn't fixed; each reports once,
    # the steps count up, and "finalize" is always last.
    assert sorted(c[0] for c in calls[:-1]) == sorted(main.MODULES)
    assert calls[-1][0] == "finalize"
    assert [c[1] for c in calls] == [1, 2, 3, 4]
    assert all(c[2] == 4 for c in calls)


def test_run_pipeline_has_error_reflects_module_errors(tmp_path):
    config = TranceConfig(case_name="c1", output_dir=tmp_path)
    pipeline = main.run_pipeline(config, _EMPTY_MODULE_KWARGS)
    assert pipeline.has_error is False  # every module skipped, not errored, with no evidence


def _slow_first_module(monkeypatch, order: list[str]):
    """Make the first module finish last, so completion order differs from MODULES order."""
    import time

    from core.schema import ModuleResult

    def fake(name, config, kwargs):
        if name == main.MODULES[0]:
            time.sleep(0.3)
        order.append(name)
        return ModuleResult(module=name, status="skipped")

    monkeypatch.setattr(main, "run_module", fake)


def test_results_and_findings_keep_module_order_whichever_finishes_first(tmp_path, monkeypatch):
    order: list[str] = []
    _slow_first_module(monkeypatch, order)
    config = TranceConfig(case_name="c1", output_dir=tmp_path)

    pipeline = main.run_pipeline(config, _EMPTY_MODULE_KWARGS)

    assert order[-1] == main.MODULES[0]  # it really did finish last
    assert [r.module for r in pipeline.results] == list(main.MODULES)
    assert list(pipeline.findings["modules"]) == list(main.MODULES)


def test_trance_workers_1_runs_the_modules_one_after_another(tmp_path, monkeypatch):
    monkeypatch.setenv("TRANCE_WORKERS", "1")
    order: list[str] = []
    _slow_first_module(monkeypatch, order)
    config = TranceConfig(case_name="c1", output_dir=tmp_path)

    main.run_pipeline(config, _EMPTY_MODULE_KWARGS)

    assert order == list(main.MODULES)


def test_run_module_records_how_long_it_took(tmp_path):
    result = main.run_module(
        "module_a_registry", TranceConfig(case_name="c1", output_dir=tmp_path), {}
    )
    assert result.duration_seconds is not None and result.duration_seconds >= 0


def test_cli_warns_that_a_full_memory_image_without_target_gives_observations_only(
    tmp_path, capsys
):
    dump = tmp_path / "fullmem.raw"
    dump.write_bytes(b"nothing here\x00")
    main.main(
        [
            "--case",
            "c1",
            "--output-dir",
            str(tmp_path / "out"),
            "--dump",
            str(dump),
            "--source-type",
            "full-memory",
        ]
    )
    err = capsys.readouterr().err
    assert "observations only" in err


def test_no_target_warning_for_a_process_dump_is_about_urls_only():
    assert "targeted URLs will be empty" in main.no_target_warning("process")
    assert "observations only" not in main.no_target_warning("process")
