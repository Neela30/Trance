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

pipeline.py (and, transitively, extractors.py's regipy import) is loaded
lazily inside run(), not at module import time — same convention
module_b_disk/module_c_memory already use for their own analysis deps.
This package also holds acquire.py (Windows-only, admin-required hive
export via reg save/vssadmin — no regipy involved at all), which needs to
stay importable and runnable without regipy installed; a top-level
`from .pipeline import ...` here would force every import of this
package, acquire.py included, to require it. cli.py's standalone
entrypoint already imports run_module_a()/write_output() directly from
.pipeline rather than through this package, so nothing else needs those
names re-exported at the package level either.
"""

from __future__ import annotations

from dataclasses import asdict
from pathlib import Path

from core.config import TranceConfig
from core.exceptions import IntegrityError
from core.schema import ModuleResult

from .normalize import MODULE_NAME

__all__ = ["run"]


def run(
    config: TranceConfig,
    ntuser: Path | None = None,
    system: Path | None = None,
    amcache: Path | None = None,
    **_: object,
) -> ModuleResult:
    if not any((ntuser, system, amcache)):
        return ModuleResult(module=MODULE_NAME, status="skipped", message="no registry hive supplied")

    from .pipeline import run_module_a

    try:
        result = run_module_a(config, ntuser=ntuser, system=system, amcache=amcache)
    except IntegrityError as exc:
        return ModuleResult(module=MODULE_NAME, status="error", message=str(exc))

    # Grouped by artifact_type for the report presenter (modules/module_a_registry/
    # report.py) -- ModuleResult.artifacts stays the flat Artifact list every other
    # module uses for the cross-module array; this is a presentation-only duplicate.
    findings_by_type: dict[str, list[dict]] = {}
    for finding in result.findings:
        findings_by_type.setdefault(finding.artifact_type, []).append(asdict(finding))

    return ModuleResult(
        module=MODULE_NAME,
        status="error" if result.errors else "ok",
        artifacts=result.findings,
        details={
            "summary": result.summary,
            "errors": result.errors,
            "custody_log_path": result.custody_log_path,
            "findings_by_type": findings_by_type,
            "hives_provided": {
                "ntuser": ntuser is not None,
                "system": system is not None,
                "amcache": amcache is not None,
            },
        },
        message="; ".join(result.errors) if result.errors else None,
    )
