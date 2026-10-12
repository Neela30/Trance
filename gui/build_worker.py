"""Runs a PyInstaller build on a background QThread so the GUI never freezes, and
turns the subprocess's stdout into a Qt signal the Build tab's live log reads --
modeled directly on pipeline_worker.py's PipelineWorker, except the work here is an
external subprocess (PyInstaller) rather than an in-process function call, so it reads
a real pipe instead of redirecting sys.stdout."""

from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path

from PySide6.QtCore import QThread, Signal


class BuildWorker(QThread):
    log = Signal(str)  # one line of the PyInstaller subprocess's stdout/stderr
    finished_ok = Signal(Path)  # final saved exe path
    failed = Signal(str)

    def __init__(
        self, argv: list[str], expected_exe: Path, save_to: Path, tmp_root: Path, parent=None
    ):
        super().__init__(parent)
        self._argv = argv
        self._expected_exe = expected_exe
        self._save_to = save_to
        self._tmp_root = tmp_root
        self._proc: subprocess.Popen | None = None
        self._cancelled = False

    def cancel(self) -> None:
        self._cancelled = True
        if self._proc is not None and self._proc.poll() is None:
            self._proc.terminate()

    def run(self) -> None:
        creationflags = subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0
        try:
            self._proc = subprocess.Popen(
                self._argv,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
                creationflags=creationflags,
            )
            for line in self._proc.stdout:
                self.log.emit(line.rstrip())
            return_code = self._proc.wait()
        except Exception as exc:
            self.failed.emit(f"{type(exc).__name__}: {exc}")
            self._cleanup()
            return

        if self._cancelled:
            self.failed.emit("Build cancelled.")
            self._cleanup()
            return

        if return_code != 0:
            self.failed.emit(f"PyInstaller exited with code {return_code}.")
            self._cleanup()
            return

        if not self._expected_exe.exists():
            self.failed.emit(
                f"Build reported success but no exe was found at {self._expected_exe}."
            )
            self._cleanup()
            return

        try:
            shutil.copy2(self._expected_exe, self._save_to)
        except OSError as exc:
            self.failed.emit(f"Could not save the built exe: {exc}")
            self._cleanup()
            return

        self._cleanup()
        self.finished_ok.emit(self._save_to)

    def _cleanup(self) -> None:
        shutil.rmtree(self._tmp_root, ignore_errors=True)
