"""Runs main.run_pipeline() on a background QThread so the analysis doesn't block the UI,
and turns its progress_cb calls (and its own print() output) into Qt signals the Analyse
tab reads for the progress bar and the live log."""

from __future__ import annotations

import contextlib

from PySide6.QtCore import QThread, Signal

import main
from core.config import TranceConfig


class _LineEmittingStream:
    """Minimal writable stream: buffers partial writes, emits one signal per complete
    line. Stands in for sys.stdout via contextlib.redirect_stdout so main.run_pipeline's
    existing print() calls -- the same per-module status lines the CLI already shows --
    reach the GUI without duplicating that formatting logic here."""

    def __init__(self, emit_line):
        self._emit_line = emit_line
        self._buffer = ""

    def write(self, text: str) -> int:
        self._buffer += text
        while "\n" in self._buffer:
            line, self._buffer = self._buffer.split("\n", 1)
            if line:
                self._emit_line(line)
        return len(text)

    def flush(self) -> None:
        pass


class PipelineWorker(QThread):
    progress = Signal(str, int, int)  # step_name, step, total_steps
    log = Signal(str)  # one line of main.run_pipeline's own print() output
    finished_ok = Signal(object)  # main.PipelineResult
    failed = Signal(str)

    def __init__(self, config: TranceConfig, module_kwargs: dict[str, dict], parent=None):
        super().__init__(parent)
        self._config = config
        self._module_kwargs = module_kwargs

    def run(self) -> None:
        stream = _LineEmittingStream(self.log.emit)
        try:
            with contextlib.redirect_stdout(stream):
                result = main.run_pipeline(
                    self._config,
                    self._module_kwargs,
                    progress_cb=lambda name, step, total: self.progress.emit(name, step, total),
                )
        except Exception as exc:  # a module's own errors are already caught inside
            self.failed.emit(f"{type(exc).__name__}: {exc}")  # run_pipeline; this is a
            return  # pipeline-level failure (e.g. can't write findings.json)
        self.finished_ok.emit(result)
