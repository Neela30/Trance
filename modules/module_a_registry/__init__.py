"""Module A — Registry & Execution Evidence.

Parses NTUSER.DAT, SYSTEM, and Amcache.hve to establish whether Tor Browser
was installed/run on the target machine and its approximate execution
timeline. See modules/module_a_registry/pipeline.py for the orchestration
and TRANCE_Project_and_ModuleA_Description.pdf section 2 for the design
brief this module implements.

run() is the pipeline entry point every modules/<name>/__init__.py must
expose (see README's "Module contract") — a thin adapter translating
pipeline.py's own ModuleAResult into core.schema.ModuleResult so main.py
can drive this module the same way it drives module_b_disk/module_c_memory.
run_module_a()/write_output() stay directly importable too, since cli.py's
standalone entrypoint (and any ad-hoc use) depends on them independent of
this pipeline-contract wrapper.
"""

from __future__ import annotations

from pathlib import Path

from core.config import TranceConfig
from core.exceptions import IntegrityError
from core.schema import ModuleResult

from .normalize import MODULE_NAME
from .pipeline import ModuleAResult, run_module_a, write_output

__all__ = ["run", "run_module_a", "write_output", "ModuleAResult"]


def run(
    config: TranceConfig,
    ntuser: Path | None = None,
    system: Path | None = None,
    amcache: Path | None = None,
    **_: object,
) -> ModuleResult:
    if not any((ntuser, system, amcache)):
        return ModuleResult(module=MODULE_NAME, status="skipped", message="no registry hive supplied")

    try:
        result = run_module_a(config, ntuser=ntuser, system=system, amcache=amcache)
    except IntegrityError as exc:
        return ModuleResult(module=MODULE_NAME, status="error", message=str(exc))

    return ModuleResult(
        module=MODULE_NAME,
        status="error" if result.errors else "ok",
        artifacts=result.findings,
        details={
            "summary": result.summary,
            "errors": result.errors,
            "custody_log_path": result.custody_log_path,
        },
        message="; ".join(result.errors) if result.errors else None,
    )
