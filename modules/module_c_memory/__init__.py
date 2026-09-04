"""Module C — memory forensics.

Acquire with dumper.py (Windows, live), analyze with analyzer.py (anywhere, offline).
run() is the pipeline entry: it only analyzes an existing dump — acquisition stays a
separate, deliberate step because process memory only exists while firefox.exe runs.
"""

from __future__ import annotations

from pathlib import Path

from core.config import TranceConfig
from core.exceptions import TranceError
from core.schema import Artifact, ModuleResult

MODULE_NAME = "module_c_memory"


def run(
    config: TranceConfig,
    dump: Path | None = None,
    onion: str | None = None,
    host: str | None = None,
    username: str | None = None,
    **_: object,
) -> ModuleResult:
    if dump is None:
        return ModuleResult(module=MODULE_NAME, status="skipped", message="no --dump supplied")

    from modules.module_c_memory.analyzer import analyze

    try:
        details = analyze(Path(dump), onion, host, username)
    except TranceError as exc:
        return ModuleResult(module=MODULE_NAME, status="error", message=str(exc))

    # Artifacts go to the cross-module list; everything else stays as this module's details.
    artifacts = [Artifact(**a) for a in details.pop("artifacts")]
    return ModuleResult(module=MODULE_NAME, status="ok", artifacts=artifacts, details=details)
