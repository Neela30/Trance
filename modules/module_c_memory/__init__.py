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

--vol3-extract-process (e.g. "firefox.exe") is a third, optional thing --vol3-path can do,
on top of the five-plugin structural pass: before string-carving, use Volatility3 to find
that process's PID (windows.pslist) and pull just its resident pages out of the full image
(windows.memmap --dump) via volatility_analyze.extract_target_process(), then run
analyzer.analyze() against that far smaller, far less noisy extract instead of the whole
image. This is what actually fixes full-memory's "every process in scope" noise problem
for extraction, as opposed to analyzer.py's host_anchoring, which papers over it after the
fact by requiring proximity to a target-host mention. Best-effort and reversible: if
discovery/extraction fails for any reason (most commonly: the process already exited by
capture time, so pslist can't see it -- see volatility_analyze.find_process_pid's
docstring), this silently falls back to analyzing the original full image, which is
already known to work.
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


def _extract_process(
    image: Path, output_dir: Path, vol3_path: str, process_name: str, pid: int | None
) -> dict:
    """Best-effort process-scoped extraction; never raises for the module — a genuine
    Volatility3 invocation failure here still degrades to a status the caller falls back
    on, same contract as extract_target_process() itself."""
    from modules.module_c_memory.volatility_analyze import extract_target_process

    try:
        return extract_target_process(vol3_path, image, output_dir, process_name=process_name, pid=pid)
    except AnalysisError as exc:
        return {"status": "error", "message": str(exc), "discovery": None, "source_image": str(image), "dump_path": None}


def run(
    config: TranceConfig,
    dump: Path | None = None,
    onion: str | None = None,
    host: str | None = None,
    username: str | None = None,
    source_type: str = "process",
    vol3_path: str | None = None,
    vol3_extract_process: str | None = None,
    vol3_extract_pid: int | None = None,
    **_: object,
) -> ModuleResult:
    if dump is None:
        return ModuleResult(module=MODULE_NAME, status="skipped", message="no --dump supplied")

    from modules.module_c_memory.analyzer import analyze

    dump_path = Path(dump)
    analyzer_dump_path, analyzer_source_type = dump_path, source_type
    process_extraction: dict | None = None

    if vol3_path and vol3_extract_process and source_type == "full-memory":
        process_extraction = _extract_process(
            dump_path,
            config.output_dir / MODULE_NAME / "extracted",
            vol3_path,
            vol3_extract_process,
            vol3_extract_pid,
        )
        if process_extraction["status"] == "ok":
            # Narrowed to one process's pages now -- back to process-scoped thresholds.
            analyzer_dump_path = Path(process_extraction["dump_path"])
            analyzer_source_type = "process"

    try:
        details = analyze(analyzer_dump_path, onion, host, username, source_type=analyzer_source_type)
    except TranceError as exc:
        return ModuleResult(module=MODULE_NAME, status="error", message=str(exc))

    if process_extraction is not None:
        details["process_extraction"] = process_extraction
    details["volatility3"] = _run_volatility3(dump_path, vol3_path)

    # Artifacts go to the cross-module list; everything else stays as this module's details.
    artifacts = [Artifact(**a) for a in details.pop("artifacts")]
    return ModuleResult(module=MODULE_NAME, status="ok", artifacts=artifacts, details=details)
