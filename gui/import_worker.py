"""Runs gui.evidence_import.import_evidence() on a background QThread for the Analyse tab:
progress and the result as signals, Cancel as a flag the copy loop checks between chunks.
The logic itself is Qt-free in evidence_import.py."""

from __future__ import annotations

import threading
from pathlib import Path

from PySide6.QtCore import QThread, Signal

from gui.evidence_import import EvidenceImportError, ImportCancelled, import_evidence

PROGRESS_STEP = 32 * 1024 * 1024  # emit at most once per 32 MB within one file


class ImportWorker(QThread):
    progress = Signal(str, object, object)  # current file, bytes done, bytes total (may be > 2 GB)
    finished_ok = Signal(object)  # gui.evidence_import.ImportResult
    failed = Signal(str)
    cancelled = Signal()

    def __init__(self, source: Path, store: Path, parent=None):
        super().__init__(parent)
        self._source = source
        self._store = store
        self._cancel = threading.Event()
        self._last: tuple[str, int] = ("", -PROGRESS_STEP)

    def cancel(self) -> None:
        self._cancel.set()

    def run(self) -> None:
        try:
            result = import_evidence(
                self._source,
                self._store,
                on_progress=self._on_progress,
                should_cancel=self._cancel.is_set,
            )
        except ImportCancelled:
            self.cancelled.emit()
        except EvidenceImportError as exc:
            self.failed.emit(str(exc))
        except Exception as exc:
            self.failed.emit(f"{type(exc).__name__}: {exc}")
        else:
            self.finished_ok.emit(result)

    def _on_progress(self, name: str, done: int, total: int) -> None:
        last_name, last_done = self._last
        if name != last_name or done - last_done >= PROGRESS_STEP or done == total:
            self._last = (name, done)
            self.progress.emit(name, done, total)
