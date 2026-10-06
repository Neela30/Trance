from pathlib import Path

from core.config import TranceConfig
from core.schema import ModuleResult
from findings import build_findings


def test_warnings_surface_at_the_top_level_module_summary():
    """core.schema.ModuleResult's own docstring: a module reporting "partial" carries
    details["warnings"] -- build_findings() must also surface it one level up, directly
    on the per-module summary dict, since that's what root report.py's Module-status
    card iterates (`findings["modules"].items()`), not `details` itself."""
    config = TranceConfig(case_name="case", output_dir=Path("."))
    result = ModuleResult(
        module="module_a_registry",
        status="partial",
        details={
            "warnings": [{"artifact_type": "ShellBags", "source": "UsrClass.dat", "reason": "boom"}]
        },
    )

    findings = build_findings(config, [result])

    assert findings["modules"]["module_a_registry"]["warnings"] == [
        {"artifact_type": "ShellBags", "source": "UsrClass.dat", "reason": "boom"}
    ]


def test_warnings_default_to_empty_list_when_absent():
    config = TranceConfig(case_name="case", output_dir=Path("."))
    result = ModuleResult(module="module_c_memory", status="ok", details={})

    findings = build_findings(config, [result])

    assert findings["modules"]["module_c_memory"]["warnings"] == []
