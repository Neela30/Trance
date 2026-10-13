"""Runs a gui.build_runner.BuildJob on a background QThread so the GUI never freezes, and
turns its output into signals for the Build tab's live log. All the logic (PyInstaller child
process, cancel, hashing, copying) lives in the Qt-free build_runner; this is only the
thread + signal plumbing."""

from __future__ import annotations

from PySide6.QtCore import QThread, Signal

from gui.build_runner import BuildCancelled, BuildError, BuildJob


class BuildWorker(QThread):
    log = Signal(str)  # one line of PyInstaller's output, or a bundle step
    finished_ok = Signal(object)  # gui.build_runner.BuildResult
    failed = Signal(str)
    cancelled = Signal()

    def __init__(self, job: BuildJob, parent=None):
        super().__init__(parent)
        self._job = job

    def cancel(self) -> None:
        self._job.cancel()

    def run(self) -> None:
        try:
            result = self._job.run(self.log.emit)
        except BuildCancelled:
            self.cancelled.emit()
        except BuildError as exc:
            self.failed.emit(str(exc))
        except Exception as exc:
            self.failed.emit(f"{type(exc).__name__}: {exc}")
        else:
            self.finished_ok.emit(result)
