"""Module C — memory forensics.

Two acquisition paths, two independent analysis passes over whatever they produced:
  - dumper.py           — Windows, live: a target process's readable committed memory.
  - winpmem_acquire.py  — Windows, live: the whole physical address space, so an already-
                           exited process's freed/unmapped pages can still be recovered.
  - analyzer.py          — anywhere, offline: raw byte-pattern string carving.
  - volatility_analyze.py — anywhere, offline: structural parsing of kernel data
                            (process pool allocations, network/file/registry state) via
                            Volatility3. Independent of analyzer.py, not a merge with it —
                            see details["volatility3"] and every row's "source" tag.

run() is the pipeline entry: it only analyzes an existing dump/image — acquisition stays
a separate, deliberate step (needs an elevated Windows session either way), not something
main.py triggers on an examiner's analysis machine. --source-type is provenance only: it
tells the analyzer/report which acquisition path produced the given file (a whole-RAM
image is bigger and noisier than one process's memory, so it also raises the per-category
result cap — see analyzer.SOURCE_TYPE_RECORD_CAPS) and never invokes dumper.py or
winpmem_acquire.py itself. Likewise --vol3-path only ever *analyzes* the given --dump; it
never triggers acquisition.
"""

from __future__ import annotations

from pathlib import Path

from core.config import TranceConfig
from core.exceptions import AnalysisError, TranceError
from core.schema import Artifact, ModuleResult

MODULE_NAME = "module_c_memory"


def _run_volatility3(image: Path, vol3_path: str | None) -> dict:
    """Best-effort structural pass; never raises — a missing/broken Volatility3 install
    degrades to details["volatility3"]["status"] == "skipped"/"error" so the module's
    overall status stays whatever the string-carver pass already achieved."""
    if vol3_path is None:
        return {"status": "skipped", "message": "no --vol3-path supplied", "plugins": {}}

    from modules.module_c_memory.volatility_analyze import analyze as vol3_analyze

    try:
        result = vol3_analyze(image, vol_path=vol3_path)
    except AnalysisError as exc:
        return {"status": "error", "message": str(exc), "plugins": {}}
    return {"status": "ok", "message": None, **result}


def run(
    config: TranceConfig,
    dump: Path | None = None,
    onion: str | None = None,
    host: str | None = None,
    username: str | None = None,
    source_type: str = "process",
    vol3_path: str | None = None,
    **_: object,
) -> ModuleResult:
    if dump is None:
        return ModuleResult(module=MODULE_NAME, status="skipped", message="no --dump supplied")

    from modules.module_c_memory.analyzer import analyze

    try:
        details = analyze(Path(dump), onion, host, username, source_type=source_type)
    except TranceError as exc:
        return ModuleResult(module=MODULE_NAME, status="error", message=str(exc))

    details["volatility3"] = _run_volatility3(Path(dump), vol3_path)

    # Artifacts go to the cross-module list; everything else stays as this module's details.
    artifacts = [Artifact(**a) for a in details.pop("artifacts")]
    return ModuleResult(module=MODULE_NAME, status="ok", artifacts=artifacts, details=details)
