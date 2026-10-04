"""The analysis as a child process, so the GUI can cancel it: a Python thread can't be
stopped safely mid-module, a process can. Launched as `gui_main.py --run-analysis
<request.json>` (or `trance-gui --run-analysis ...` when frozen -- PyInstaller's
sys.executable is the bundle itself, so the same binary re-launches itself).

Talks to the GUI over stdout: ordinary lines are the pipeline's own log output, and
lines starting with PROTOCOL_PREFIX carry JSON -- progress checkpoints and the final
result. No Qt import here; gui.processes owns the Qt side."""

from __future__ import annotations

import json
import sys
from dataclasses import dataclass
from pathlib import Path

PROTOCOL_PREFIX = "@@TRANCE "
ROOT = Path(__file__).resolve().parents[1]


@dataclass(frozen=True)
class RunSummary:
    """What the GUI needs from main.PipelineResult once the child has exited."""

    report_path: Path
    findings_path: Path
    has_error: bool


def runner_command(request_path: Path) -> list[str]:
    if getattr(sys, "frozen", False):
        return [sys.executable, "--run-analysis", str(request_path)]
    return [sys.executable, str(ROOT / "gui_main.py"), "--run-analysis", str(request_path)]


def _send(message: dict) -> None:
    print(PROTOCOL_PREFIX + json.dumps(message), flush=True)


def parse_line(line: str) -> tuple[str, dict | str]:
    """("progress"|"result"|"error", payload) for a protocol line, ("log", line) otherwise."""
    if line.startswith(PROTOCOL_PREFIX):
        try:
            message = json.loads(line[len(PROTOCOL_PREFIX) :])
            return message.pop("type"), message
        except (ValueError, KeyError, AttributeError):
            pass
    return "log", line


def summary_from(payload: dict) -> RunSummary:
    return RunSummary(
        report_path=Path(payload["report_path"]),
        findings_path=Path(payload["findings_path"]),
        has_error=bool(payload["has_error"]),
    )


def run(request_path: Path) -> int:
    # Imported here: the GUI process only needs the module for runner_command/parse_line.
    import main
    from core.config import TranceConfig
    from gui.analysis_request import AnalysisRequest, effective_inputs
    from gui.pipeline_inputs import module_kwargs_from_resolved

    sys.stdout.reconfigure(line_buffering=True)
    try:
        request = AnalysisRequest.from_json(Path(request_path).read_text(encoding="utf-8"))
        inputs = effective_inputs(request)
        module_kwargs = module_kwargs_from_resolved(
            inputs, request.onion, request.host, request.username
        )
        request.case_dir.mkdir(parents=True, exist_ok=True)
        config = TranceConfig(
            case_name=request.case_name,
            output_dir=request.case_dir,
            evidence_dir=Path(request.evidence_dir) if request.evidence_dir else None,
        )
        result = main.run_pipeline(
            config,
            module_kwargs,
            progress_cb=lambda name, step, total: _send(
                {"type": "progress", "name": name, "step": step, "total": total}
            ),
        )
    except Exception as exc:  # a module's own errors are caught inside run_pipeline
        _send({"type": "error", "message": f"{type(exc).__name__}: {exc}"})
        return 1
    _send(
        {
            "type": "result",
            "report_path": str(result.report_path),
            "findings_path": str(result.findings_path),
            "has_error": result.has_error,
        }
    )
    return 0
