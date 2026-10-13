import json
import sys
import types

import pytest

import main
from core import safety
from core.config import TranceConfig
from gui import analysis_runner
from gui.analysis_request import AnalysisRequest, validate


@pytest.fixture
def as_root(monkeypatch):
    monkeypatch.setattr(safety.os, "geteuid", lambda: 0, raising=False)


def test_not_root_by_default():
    assert safety.running_as_root() is False  # the test suite never runs as root


def test_pipeline_refuses_root(tmp_path, as_root):
    config = TranceConfig(case_name="c", output_dir=tmp_path / "c")
    with pytest.raises(safety.UnsafeEnvironmentError, match="as root"):
        main.run_pipeline(config, {})
    assert not (tmp_path / "c" / "findings.json").exists()


def test_cli_refuses_root_before_creating_anything(tmp_path, as_root, capsys):
    assert main.main(["--case", "c", "--output-dir", str(tmp_path / "out")]) == 1
    assert "as root" in capsys.readouterr().err
    assert not (tmp_path / "out").exists()


def test_gui_child_refuses_root(tmp_path, as_root, capsys):
    request = AnalysisRequest(case_name="c", output_dir=str(tmp_path))
    path = tmp_path / "request.json"
    path.write_text(request.to_json())

    assert analysis_runner.run(path) == 1
    out = capsys.readouterr().out
    assert "as root" in out
    assert not (tmp_path / "c").exists()


def test_gui_form_refuses_root(tmp_path, as_root):
    request = AnalysisRequest(case_name="c", output_dir=str(tmp_path))
    assert any("root" in e for e in validate(request, {"dump": __file__}).errors)


def test_limits_are_a_no_op_off_linux(monkeypatch):
    monkeypatch.setattr(safety.sys, "platform", "win32")
    assert safety.limits_supported() is False
    assert "only applied on Linux" in safety.apply_resource_limits(1024, 60)[0]


def test_limits_set_address_space_and_cpu_on_linux(monkeypatch):
    calls = {}
    fake = types.SimpleNamespace(
        RLIMIT_AS=9,
        RLIMIT_CPU=0,
        RLIM_INFINITY=-1,
        getrlimit=lambda which: (-1, -1),
        setrlimit=lambda which, pair: calls.__setitem__(which, pair),
    )
    monkeypatch.setattr(safety.sys, "platform", "linux")
    monkeypatch.setitem(sys.modules, "resource", fake)

    notes = safety.apply_resource_limits(2048, 600)

    assert calls == {9: (2048 * 1024 * 1024,) * 2, 0: (600, 600)}
    assert any("2048 MB" in n for n in notes) and any("600 s" in n for n in notes)


def test_limits_never_raise_an_existing_hard_limit(monkeypatch):
    calls = {}
    fake = types.SimpleNamespace(
        RLIMIT_AS=9,
        RLIMIT_CPU=0,
        RLIM_INFINITY=-1,
        getrlimit=lambda which: (100, 100),
        setrlimit=lambda which, pair: calls.__setitem__(which, pair),
    )
    monkeypatch.setattr(safety.sys, "platform", "linux")
    monkeypatch.setitem(sys.modules, "resource", fake)

    safety.apply_resource_limits(2048, 600)
    assert calls == {9: (100, 100), 0: (100, 100)}


def test_zero_means_no_limit(monkeypatch):
    fake = types.SimpleNamespace(
        RLIMIT_AS=9,
        RLIMIT_CPU=0,
        RLIM_INFINITY=-1,
        getrlimit=lambda which: (-1, -1),
        setrlimit=lambda which, pair: pytest.fail("no limit should be set"),
    )
    monkeypatch.setattr(safety.sys, "platform", "linux")
    monkeypatch.setitem(sys.modules, "resource", fake)
    assert safety.apply_resource_limits(0, 0) == [
        "memory (address space): no limit",
        "CPU time: no limit",
    ]


def test_request_limits_default_from_environment(monkeypatch):
    monkeypatch.setenv(safety.MEMORY_LIMIT_ENV, "4096")
    monkeypatch.setenv(safety.CPU_LIMIT_ENV, "junk")
    request = AnalysisRequest(case_name="c", output_dir=".")
    assert request.resource_limits() == (4096, safety.DEFAULT_CPU_LIMIT_SECONDS)

    explicit = AnalysisRequest(
        case_name="c", output_dir=".", memory_limit_mb=0, cpu_limit_seconds=5
    )
    assert explicit.resource_limits() == (0, 5)
    assert json.loads(explicit.to_json())["cpu_limit_seconds"] == 5


def test_negative_limit_is_a_form_error(tmp_path):
    request = AnalysisRequest(case_name="c", output_dir=str(tmp_path), memory_limit_mb=-1)
    assert any("Memory limit" in e for e in validate(request, {"dump": __file__}).errors)


def test_child_applies_limits_before_reading_evidence(tmp_path, monkeypatch, capsys):
    applied = []
    monkeypatch.setattr(
        "core.safety.apply_resource_limits",
        lambda memory, cpu: applied.append((memory, cpu)) or ["memory: limited"],
    )
    monkeypatch.setattr(
        "gui.analysis_request.effective_inputs",
        lambda request: applied.append("inputs") or {},
    )
    request = AnalysisRequest(
        case_name="c", output_dir=str(tmp_path), memory_limit_mb=1024, cpu_limit_seconds=60
    )
    path = tmp_path / "request.json"
    path.write_text(request.to_json())

    assert analysis_runner.run(path) == 0
    assert applied[:2] == [(1024, 60), "inputs"]
    assert "resource limit: memory: limited" in capsys.readouterr().out
