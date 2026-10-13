"""Build tab: packages acquire_all.py into a single standalone trance-acquire.exe via
PyInstaller, so it can be copied to a target machine with no Python installed. Visual recipe
(720px centered column, masthead with StatusIndicator, live log) copied from analyse_tab.py,
but this tab has no case/history concept -- it's a standalone build action, not part of the
Analyse -> Report -> History flow, so it gets its own tab.

The logic is Qt-free in gui/build_runner.py (PyInstaller child process, Cancel, SHA-256
sidecar, the optional verified copy to a tools drive with a WinPMEM binary); this file is only
the form. PyInstaller can't cross-compile, so off Windows the button is disabled with the
reason shown."""

from __future__ import annotations

from pathlib import Path

from PySide6.QtCore import Qt, QUrl
from PySide6.QtGui import QDesktopServices
from PySide6.QtWidgets import (
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QMessageBox,
    QPlainTextEdit,
    QProgressBar,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from gui.advanced_inputs import PathPicker, field_label, labelled
from gui.build_inputs import (
    ACQUIRE_SCRIPT,
    DEFAULT_BUILDS_DIR,
    build_support,
    check_prerequisites,
    elevation_warning,
)
from gui.build_runner import BuildJob
from gui.build_worker import BuildWorker
from gui.theme import StatusIndicator, apply_eyebrow_style, apply_heading_style

FORM_MAX_WIDTH = 720
RUN_BUTTON_WIDTH = 240
EXE_FILTER = "Programs (*.exe);;All files (*)"


class BuildTab(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self._worker: BuildWorker | None = None
        self._result = None
        self._supported, self._unsupported_reason = build_support()

        content = QWidget(self)
        content.setMaximumWidth(FORM_MAX_WIDTH)
        content_layout = QVBoxLayout(content)
        content_layout.setContentsMargins(0, 24, 0, 24)

        content_layout.addLayout(self._build_masthead())
        content_layout.addSpacing(16)
        content_layout.addWidget(self._build_info_box())
        content_layout.addSpacing(8)
        content_layout.addWidget(self._build_options_box())
        content_layout.addSpacing(4)
        content_layout.addLayout(self._build_run_row())
        content_layout.addSpacing(14)
        content_layout.addWidget(self._progress)
        content_layout.addWidget(self._status_label)
        content_layout.addSpacing(20)
        content_layout.addWidget(self._build_log_box())
        content_layout.addStretch(1)

        outer = QHBoxLayout(self)
        outer.addStretch(1)
        outer.addWidget(content)
        outer.addStretch(1)

        if not self._supported:
            self._build_button.setEnabled(False)
            self._stamp.set_status("skipped")
            self._stamp.set_text("Windows only")

    # -- construction -----------------------------------------------------------

    def _build_masthead(self) -> QHBoxLayout:
        eyebrow = QLabel("Trance", self)
        apply_eyebrow_style(eyebrow)
        heading = QLabel("Build acquisition tool", self)
        apply_heading_style(heading)
        heading_col = QVBoxLayout()
        heading_col.addWidget(eyebrow)
        heading_col.addWidget(heading)

        status_eyebrow = QLabel("Status", self)
        apply_eyebrow_style(status_eyebrow)
        status_eyebrow.setAlignment(Qt.AlignmentFlag.AlignRight)
        self._stamp = StatusIndicator("Ready", self)
        self._stamp.set_status("ok")
        status_col = QVBoxLayout()
        status_col.setAlignment(Qt.AlignmentFlag.AlignRight)
        status_col.addWidget(status_eyebrow)
        status_col.addWidget(self._stamp)

        masthead = QHBoxLayout()
        masthead.addLayout(heading_col)
        masthead.addStretch(1)
        masthead.addLayout(status_col)
        return masthead

    def _build_info_box(self) -> QGroupBox:
        label = QLabel(
            "Packages acquire_all.py into trance-acquire.exe, a single file you run as "
            "Administrator on the suspect machine (no Python needed there). A SHA-256 file "
            "is written next to it so the tools drive can be checked before use.",
            self,
        )
        label.setWordWrap(True)
        label.setStyleSheet("color: #8b969c;")

        script_label = QLabel(f"Script: {ACQUIRE_SCRIPT.name}", self)
        apply_eyebrow_style(script_label, f"Script: {ACQUIRE_SCRIPT.name}")

        box = QGroupBox(self)
        layout = QVBoxLayout()
        layout.addWidget(label)
        if not self._supported:
            reason = QLabel(self._unsupported_reason, self)
            reason.setWordWrap(True)
            reason.setStyleSheet("color: #c9a552;")
            layout.addSpacing(6)
            layout.addWidget(reason)
        layout.addSpacing(6)
        layout.addWidget(script_label)
        box.setLayout(layout)
        return box

    def _build_options_box(self) -> QGroupBox:
        self._output_picker = PathPicker("Choose a folder", is_dir=True, parent=self)
        self._output_picker.set_path(str(DEFAULT_BUILDS_DIR))
        self._copy_picker = PathPicker(
            "Not set — the build stays in the save folder", is_dir=True, parent=self
        )
        self._winpmem_picker = PathPicker(
            "Not set — memory imaging needs one on the target",
            is_dir=False,
            file_filter=EXE_FILTER,
            parent=self,
        )

        box = QGroupBox(self)
        layout = QVBoxLayout()
        layout.setSpacing(14)
        layout.addLayout(
            labelled(
                field_label("Save to", self),
                self._output_picker,
                "A new trance-acquire-<date> folder is created here; nothing existing is "
                "overwritten.",
                self,
            )
        )
        layout.addLayout(
            labelled(
                field_label("Also copy to (tools drive)", self),
                self._copy_picker,
                "Optional: the same folder is copied here and every file re-checked "
                "against its SHA-256. Write-protect the drive afterwards.",
                self,
            )
        )
        layout.addLayout(
            labelled(
                field_label("WinPMEM binary", self),
                self._winpmem_picker,
                "Optional: bundled with its own SHA-256 so trance-acquire finds it next to "
                "itself for full-memory capture.",
                self,
            )
        )
        if not self._supported:
            for picker in (self._output_picker, self._copy_picker, self._winpmem_picker):
                picker.setEnabled(False)
        box.setLayout(layout)
        return box

    def _build_run_row(self) -> QHBoxLayout:
        self._build_button = QPushButton("Build trance-acquire.exe", self)
        self._build_button.setProperty("class", "primary")
        self._build_button.setFixedWidth(RUN_BUTTON_WIDTH)
        self._build_button.clicked.connect(self._start_build)

        self._cancel_button = QPushButton("Cancel", self)
        self._cancel_button.setProperty("class", "danger")
        self._cancel_button.clicked.connect(self._cancel_build)
        self._cancel_button.setVisible(False)

        self._open_folder_button = QPushButton("Open folder", self)
        self._open_folder_button.clicked.connect(self._open_folder)
        self._open_folder_button.setVisible(False)

        self._progress = QProgressBar(self)
        self._progress.setRange(0, 100)
        self._progress.setValue(0)
        self._status_label = QLabel("", self)
        self._status_label.setWordWrap(True)
        apply_eyebrow_style(self._status_label, "")

        run_row = QHBoxLayout()
        run_row.addStretch(1)
        run_row.addWidget(self._build_button)
        run_row.addWidget(self._cancel_button)
        run_row.addWidget(self._open_folder_button)
        run_row.addStretch(1)
        return run_row

    def _build_log_box(self) -> QGroupBox:
        eyebrow = QLabel("Build log", self)
        apply_eyebrow_style(eyebrow)

        self._log_view = QPlainTextEdit(self)
        self._log_view.setReadOnly(True)
        self._log_view.setMaximumBlockCount(2000)
        self._log_view.setStyleSheet(
            "QPlainTextEdit { font-family: 'Cascadia Code', Consolas, monospace; "
            "font-size: 11.5px; background: #14181b; border: none; color: #8b969c; }"
        )

        layout = QVBoxLayout()
        layout.addWidget(eyebrow)
        layout.addWidget(self._log_view)

        box = QGroupBox(self)
        box.setLayout(layout)
        return box

    # -- behavior -----------------------------------------------------------

    def _start_build(self) -> None:
        if not self._supported:
            return
        problems = check_prerequisites()
        if not self._output_picker.path():
            problems.append("Choose a folder to save the build to.")
        job = BuildJob(
            Path(self._output_picker.path() or "."),
            copy_to=Path(self._copy_picker.path()) if self._copy_picker.path() else None,
            winpmem=Path(self._winpmem_picker.path()) if self._winpmem_picker.path() else None,
        )
        problems += job.preflight() if self._output_picker.path() else []
        if problems:
            QMessageBox.warning(self, "Can't build yet", "\n\n".join(problems))
            return

        warning = elevation_warning()
        if warning:
            answer = QMessageBox.warning(
                self,
                "Running as administrator",
                warning + "\n\nBuild anyway?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.No,
            )
            if answer != QMessageBox.StandardButton.Yes:
                return

        self._build_button.setEnabled(False)
        self._cancel_button.setVisible(True)
        self._cancel_button.setEnabled(True)
        self._open_folder_button.setVisible(False)
        self._progress.setRange(0, 0)
        self._stamp.set_status("skipped")
        self._stamp.set_text("Building")
        apply_eyebrow_style(self._status_label, "Building…")
        self._log_view.clear()
        if warning:
            self._log_view.appendPlainText(f"[!] {warning}")

        self._worker = BuildWorker(job, self)
        self._worker.log.connect(self._log_view.appendPlainText)
        self._worker.finished_ok.connect(self._on_finished)
        self._worker.failed.connect(self._on_failed)
        self._worker.cancelled.connect(self._on_cancelled)
        self._worker.start()

    def _cancel_build(self) -> None:
        if self._worker is not None:
            self._cancel_button.setEnabled(False)
            apply_eyebrow_style(self._status_label, "Cancelling…")
            self._worker.cancel()

    def shutdown(self) -> None:
        """Called when the window closes: stop PyInstaller and wait for the thread."""
        if self._worker is not None and self._worker.isRunning():
            self._worker.cancel()
            self._worker.wait(10000)

    def _end(self, status: str, stamp: str, message: str) -> None:
        self._progress.setRange(0, 100)
        self._progress.setValue(100 if status == "ok" else 0)
        self._build_button.setEnabled(True)
        self._cancel_button.setVisible(False)
        self._stamp.set_status(status)
        self._stamp.set_text(stamp)
        apply_eyebrow_style(self._status_label, message)

    def _on_finished(self, result) -> None:
        self._result = result
        where = f"Saved to {result.output_dir}"
        if result.copy_dir:
            where += f" and copied to {result.copy_dir}"
        self._end("ok", "Done", f"{where}. SHA-256 {result.sha256}")
        self._open_folder_button.setVisible(True)
        if result.copy_dir:
            QMessageBox.information(
                self,
                "Tools drive ready",
                f"trance-acquire.exe and its SHA-256 were copied to\n{result.copy_dir}\n"
                "and verified.\n\nWrite-protect the drive (or eject it) before taking it to "
                "the suspect machine.",
            )

    def _on_failed(self, message: str) -> None:
        self._end("error", "Failed", "Failed.")
        QMessageBox.critical(self, "Build failed", message)

    def _on_cancelled(self) -> None:
        self._log_view.appendPlainText("[*] cancelled.")
        self._end("skipped", "Cancelled", "Cancelled. Nothing was kept.")

    def _open_folder(self) -> None:
        if self._result is not None:
            QDesktopServices.openUrl(QUrl.fromLocalFile(str(self._result.output_dir)))
