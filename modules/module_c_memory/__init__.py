"""Module C — memory forensics.

Two acquisition paths, one analyzer:
  - dumper.py           — Windows, live: a target process's readable committed memory.
  - winpmem_acquire.py  — Windows, live: the whole physical address space, so an already-
                           exited process's freed/unmapped pages can still be recovered.
analyzer.py runs anywhere, offline, against whatever image either path produced.

run() is the pipeline entry: it only analyzes an existing dump/image — acquisition stays
a separate, deliberate step (needs an elevated Windows session either way), not something
main.py triggers on an examiner's analysis machine. --source-type is provenance only: it
tells the analyzer/report which acquisition path produced the given file (a whole-RAM
image is bigger and noisier than one process's memory, so it also raises the per-category
result cap — see analyzer.SOURCE_TYPE_RECORD_CAPS) and never invokes dumper.py or
winpmem_acquire.py itself.
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
    source_type: str = "process",
    **_: object,
) -> ModuleResult:
    if dump is None:
        return ModuleResult(module=MODULE_NAME, status="skipped", message="no --dump supplied")

    from modules.module_c_memory.analyzer import analyze

    try:
        details = analyze(Path(dump), onion, host, username, source_type=source_type)
    except TranceError as exc:
        return ModuleResult(module=MODULE_NAME, status="error", message=str(exc))

    # Artifacts go to the cross-module list; everything else stays as this module's details.
    artifacts = [Artifact(**a) for a in details.pop("artifacts")]
    return ModuleResult(module=MODULE_NAME, status="ok", artifacts=artifacts, details=details)
