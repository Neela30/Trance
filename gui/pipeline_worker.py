"""Runs main.run_pipeline() on a background QThread so the analysis doesn't block the UI,
and turns its progress_cb calls into Qt signals the Analyse tab's progress bar reads."""

from __future__ import annotations

from PySide6.QtCore import QThread, Signal

import main
from core.config import TranceConfig


class PipelineWorker(QThread):
    progress = Signal(str, int, int)  # step_name, step, total_steps
    finished_ok = Signal(object)  # main.PipelineResult
    failed = Signal(str)

    def __init__(self, config: TranceConfig, module_kwargs: dict[str, dict], parent=None):
        super().__init__(parent)
        self._config = config
        self._module_kwargs = module_kwargs

    def run(self) -> None:
        try:
            result = main.run_pipeline(
                self._config,
                self._module_kwargs,
                progress_cb=lambda name, step, total: self.progress.emit(name, step, total),
            )
        except Exception as exc:  # a module's own errors are already caught inside
            self.failed.emit(f"{type(exc).__name__}: {exc}")  # run_pipeline; this is a
            return  # pipeline-level failure (e.g. can't write findings.json)
        self.finished_ok.emit(result)
