"""Qt side of the two child processes the Analyse tab drives:

  AnalysisProcess  runs the pipeline (gui.analysis_runner) so it can be cancelled
  MountSession     runs gui.mount_helper through pkexec to mount a disk image

Both turn their child's stdout into signals; the protocols themselves live in the
Qt-free modules so they're unit-tested without PySide6."""

from __future__ import annotations

import json
import os
import shutil
import sys
import tempfile
from pathlib import Path

from PySide6.QtCore import QObject, QProcess, QProcessEnvironment, QTimer, Signal

from gui.analysis_request import AnalysisRequest
from gui.analysis_runner import ROOT, parse_line, runner_command, summary_from

CANCEL_GRACE_MS = 3000
MOUNT_TOOLS = ("pkexec", "qemu-nbd", "ntfs-3g", "lsblk", "udevadm")


def _split_lines(buffer: str) -> tuple[list[str], str]:
    """Complete lines (on \\n or \\r -- the raw carver redraws its progress with \\r)
    plus the unfinished remainder."""
    parts = buffer.replace("\r\n", "\n").replace("\r", "\n").split("\n")
    return [p for p in parts[:-1] if p.strip()], parts[-1]


class AnalysisProcess(QObject):
    progress = Signal(str, int, int)  # step name, step, total steps
    log = Signal(str)
    activity = Signal(str)  # transient status (e.g. carve progress), not worth a log line
    finished_ok = Signal(object)  # gui.analysis_runner.RunSummary
    failed = Signal(str)
    cancelled = Signal()

    def __init__(self, parent=None):
        super().__init__(parent)
        self._process: QProcess | None = None
        self._request_file: Path | None = None
        self._stdout = self._stderr = ""
        self._summary = None
        self._error: str | None = None
        self._stderr_tail: list[str] = []
        self._cancelling = False

    def is_running(self) -> bool:
        return self._process is not None and self._process.state() != QProcess.NotRunning

    def start(self, request: AnalysisRequest) -> None:
        handle, name = tempfile.mkstemp(prefix="trance-request-", suffix=".json")
        with os.fdopen(handle, "w", encoding="utf-8") as stream:
            stream.write(request.to_json())
        self._request_file = Path(name)
        self._stdout = self._stderr = ""
        self._summary, self._error, self._stderr_tail = None, None, []
        self._cancelling = False

        command = runner_command(self._request_file)
        process = QProcess(self)
        environment = QProcessEnvironment.systemEnvironment()
        environment.insert("PYTHONUNBUFFERED", "1")
        process.setProcessEnvironment(environment)
        process.setWorkingDirectory(str(ROOT))
        process.readyReadStandardOutput.connect(self._read_stdout)
        process.readyReadStandardError.connect(self._read_stderr)
        process.finished.connect(self._on_finished)
        process.errorOccurred.connect(self._on_error)
        self._process = process
        process.start(command[0], command[1:])

    def cancel(self) -> None:
        if not self.is_running():
            return
        self._cancelling = True
        self._process.terminate()
        QTimer.singleShot(CANCEL_GRACE_MS, self._kill_if_running)

    def kill_and_wait(self) -> None:
        """For application shutdown: no grace period, block until it's gone."""
        if self.is_running():
            self._cancelling = True
            self._process.kill()
            self._process.waitForFinished(5000)

    def _kill_if_running(self) -> None:
        if self.is_running():
            self._process.kill()

    def _read_stdout(self) -> None:
        self._stdout += bytes(self._process.readAllStandardOutput()).decode(errors="replace")
        lines, self._stdout = _split_lines(self._stdout)
        for line in lines:
            kind, payload = parse_line(line)
            if kind == "progress":
                self.progress.emit(payload["name"], payload["step"], payload["total"])
            elif kind == "result":
                self._summary = summary_from(payload)
            elif kind == "error":
                self._error = payload["message"]
            else:
                self.log.emit(line)

    def _read_stderr(self) -> None:
        self._stderr += bytes(self._process.readAllStandardError()).decode(errors="replace")
        lines, self._stderr = _split_lines(self._stderr)
        for line in lines:
            if line.lstrip().startswith("scanned "):
                self.activity.emit(line.strip())
                continue
            self._stderr_tail = (self._stderr_tail + [line])[-20:]
            self.log.emit(line)

    def _on_error(self, error) -> None:
        if error == QProcess.FailedToStart:
            self._cleanup()
            self.failed.emit(
                f"Could not start the analysis process: {' '.join(runner_command(Path('…')))}"
            )

    def _on_finished(self, exit_code: int, _status) -> None:
        self._read_stdout()
        self._read_stderr()
        self._cleanup()
        if self._cancelling:
            self.cancelled.emit()
        elif self._summary is not None:
            self.finished_ok.emit(self._summary)
        else:
            detail = self._error or "\n".join(self._stderr_tail[-8:]) or f"exit code {exit_code}"
            self.failed.emit(detail)

    def _cleanup(self) -> None:
        if self._request_file:
            self._request_file.unlink(missing_ok=True)
            self._request_file = None


def mount_support() -> tuple[bool, str]:
    """Whether this machine can mount images from the GUI, and why not if it can't."""
    if not sys.platform.startswith("linux"):
        return False, "Mounting disk images from the app is supported on Linux only."
    missing = [tool for tool in MOUNT_TOOLS if shutil.which(tool) is None]
    if missing:
        return False, (
            f"Missing tools: {', '.join(missing)} "
            "(install qemu-utils and ntfs-3g; pkexec comes with polkit)."
        )
    return True, ""


def mount_helper_command(image: Path) -> list[str]:
    if getattr(sys, "frozen", False):
        helper = [sys.executable, "--mount-helper"]
    else:
        helper = [sys.executable, str(ROOT / "gui" / "mount_helper.py")]
    return [shutil.which("pkexec") or "pkexec", *helper, "session", str(image.resolve())]


class MountSession(QObject):
    mounted = Signal(dict)  # the helper's "mounted" event: mountpoint, partition, ...
    failed = Signal(str)
    unmounted = Signal(list)  # problems during cleanup, usually empty

    def __init__(self, parent=None):
        super().__init__(parent)
        self._process: QProcess | None = None
        self._buffer = ""
        self._error: str | None = None
        self._is_mounted = False
        self._unmount_sent = False

    @property
    def is_active(self) -> bool:
        return self._process is not None and self._process.state() != QProcess.NotRunning

    def start(self, image: Path) -> None:
        command = mount_helper_command(image)
        self._buffer, self._error, self._is_mounted = "", None, False
        self._unmount_sent = False
        process = QProcess(self)
        process.readyReadStandardOutput.connect(self._read)
        process.finished.connect(self._on_finished)
        self._process = process
        process.start(command[0], command[1:])

    def unmount(self) -> None:
        """Ask the helper to unmount. Safe to call more than once, and before the mount
        finished: the request waits in the helper's stdin until it gets there."""
        if self.is_active and not self._unmount_sent:
            self._unmount_sent = True
            self._process.write(b"unmount\n")
            self._process.closeWriteChannel()

    def unmount_and_wait(self, timeout_ms: int = 20000) -> None:
        if self.is_active:
            self.unmount()
            self._process.waitForFinished(timeout_ms)

    def _read(self) -> None:
        self._buffer += bytes(self._process.readAllStandardOutput()).decode(errors="replace")
        *lines, self._buffer = self._buffer.split("\n")
        for line in lines:
            try:
                event = json.loads(line)
            except ValueError:
                continue
            kind = event.pop("event", None)
            if kind == "mounted":
                self._is_mounted = True
                self.mounted.emit(event)
            elif kind == "error":
                self._error = event.get("message", "unknown error")
            elif kind == "unmounted":
                self._is_mounted = False
                self.unmounted.emit(event.get("problems", []))

    def _on_finished(self, exit_code: int, _status) -> None:
        self._read()
        stderr = bytes(self._process.readAllStandardError()).decode(errors="replace").strip()
        if self._error:
            self.failed.emit(self._error)
        elif exit_code in (126, 127) and not self._is_mounted:
            # pkexec: 126 = authentication dismissed/failed, 127 = not authorized
            self.failed.emit("Administrator authentication was cancelled or refused.")
        elif exit_code != 0 and not self._is_mounted:
            self.failed.emit(stderr or f"Mount helper exited with code {exit_code}.")
