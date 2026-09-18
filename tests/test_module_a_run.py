from pathlib import Path

from core.config import TranceConfig
from core.exceptions import IntegrityError
from core.schema import Artifact
from modules import module_a_registry
from modules.module_a_registry.pipeline import ModuleAResult


def make_config(tmp_path):
    return TranceConfig(case_name="t", output_dir=tmp_path)


def test_run_skipped_without_any_hive(tmp_path):
    result = module_a_registry.run(make_config(tmp_path))
    assert result.status == "skipped"
    assert result.artifacts == []


def test_run_ok_with_findings_and_no_errors(tmp_path, monkeypatch):
    artifact = Artifact(
        module="A_registry_execution",
        artifact_type="UserAssist",
        source="/hives/NTUSER.DAT",
        description="UserAssist evidence for 'tor.exe'",
        timestamp="2026-09-01T00:00:00",
    )

    def fake_run_module_a(config, ntuser=None, system=None, amcache=None):
        return ModuleAResult(findings=[artifact], summary="Tor Browser executed 3 times.", errors=[])

    monkeypatch.setattr(module_a_registry, "run_module_a", fake_run_module_a)
    result = module_a_registry.run(make_config(tmp_path), ntuser=tmp_path / "NTUSER.DAT")

    assert result.status == "ok"
    assert result.artifacts == [artifact]
    assert result.message is None
    assert result.details["summary"] == "Tor Browser executed 3 times."
    assert result.details["errors"] == []


def test_run_error_status_when_pipeline_reports_extraction_errors(tmp_path, monkeypatch):
    def fake_run_module_a(config, ntuser=None, system=None, amcache=None):
        return ModuleAResult(
            findings=[],
            summary="No Tor Browser artifacts found.",
            errors=["ShimCache (SYSTEM): not recognized as a SYSTEM hive."],
        )

    monkeypatch.setattr(module_a_registry, "run_module_a", fake_run_module_a)
    result = module_a_registry.run(make_config(tmp_path), system=tmp_path / "SYSTEM")

    assert result.status == "error"
    assert "not recognized as a SYSTEM hive" in result.message
    assert result.details["errors"] == ["ShimCache (SYSTEM): not recognized as a SYSTEM hive."]


def test_run_error_status_on_integrity_mismatch(tmp_path, monkeypatch):
    def fake_run_module_a(config, ntuser=None, system=None, amcache=None):
        raise IntegrityError("Hash mismatch for NTUSER.DAT")

    monkeypatch.setattr(module_a_registry, "run_module_a", fake_run_module_a)
    result = module_a_registry.run(make_config(tmp_path), ntuser=tmp_path / "NTUSER.DAT")

    assert result.status == "error"
    assert "Hash mismatch" in result.message
    assert result.artifacts == []
