"""Build EXE tab: packages acquire_all.py into a single standalone .exe via PyInstaller,
so it can be copied to a target machine with no Python installed. Visual recipe (720px
centered column, masthead with StatusIndicator, live log) copied from analyse_tab.py,
but this tab has no case/history concept -- it's a standalone build action, not part of
the Analyse -> Report -> History flow, so it gets its own tab rather than a section on
Analyse (see CLAUDE.md handoff plan for the Generate acquisition EXE feature)."""

from __future__ import annotations

import tempfile
from pathlib import Path

from PySide6.QtCore import Qt, QUrl
from PySide6.QtGui import QDesktopServices
from PySide6.QtWidgets import (
    QFileDialog,
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

from gui.build_inputs import (
    ACQUIRE_SCRIPT,
    build_pyinstaller_argv,
    built_exe_path,
    check_prerequisites,
    default_output_name,
)
from gui.build_worker import BuildWorker
from gui.theme import StatusIndicator, apply_eyebrow_style, apply_heading_style

FORM_MAX_WIDTH = 720
RUN_BUTTON_WIDTH = 240


class BuildTab(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self._worker: BuildWorker | None = None
        self._tmp_root: Path | None = None
        self._saved_path: Path | None = None

        content = QWidget(self)
        content.setMaximumWidth(FORM_MAX_WIDTH)
        content_layout = QVBoxLayout(content)
        content_layout.setContentsMargins(0, 24, 0, 24)

        content_layout.addLayout(self._build_masthead())
        content_layout.addSpacing(16)
        content_layout.addWidget(self._build_info_box())
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

    # -- construction -----------------------------------------------------------

    def _build_masthead(self) -> QHBoxLayout:
        eyebrow = QLabel("Trance", self)
        apply_eyebrow_style(eyebrow)
        heading = QLabel("Build acquisition EXE", self)
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
            "Packages acquire_all.py into a single .exe you can copy to a target "
            "machine with no Python installed. Run the built exe there as "
            "Administrator to collect registry, disk, and memory evidence.",
            self,
        )
        label.setWordWrap(True)
        label.setStyleSheet("color: #8b969c;")

        script_label = QLabel(f"Script: {ACQUIRE_SCRIPT.name}", self)
        apply_eyebrow_style(script_label, f"Script: {ACQUIRE_SCRIPT.name}")

        box = QGroupBox(self)
        layout = QVBoxLayout()
        layout.addWidget(label)
        layout.addSpacing(6)
        layout.addWidget(script_label)
        box.setLayout(layout)
        return box

    def _build_run_row(self) -> QHBoxLayout:
        self._build_button = QPushButton("Generate acquisition EXE", self)
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
        problems = check_prerequisites()
        if problems:
            QMessageBox.warning(self, "Can't build yet", "\n\n".join(problems))
            return

        save_to, _ = QFileDialog.getSaveFileName(
            self,
            "Save acquisition EXE as",
            str(Path.home() / default_output_name()),
            "Windows Executable (*.exe)",
        )
        if not save_to:
            return

        self._tmp_root = Path(tempfile.mkdtemp(prefix="trance_build_"))
        dist_dir = self._tmp_root / "dist"
        work_dir = self._tmp_root / "build"
        spec_dir = self._tmp_root / "spec"
        argv = build_pyinstaller_argv(ACQUIRE_SCRIPT, dist_dir, work_dir, spec_dir)
        expected_exe = built_exe_path(dist_dir)

        self._build_button.setEnabled(False)
        self._cancel_button.setVisible(True)
        self._open_folder_button.setVisible(False)
        self._progress.setRange(0, 0)
        self._stamp.set_status("skipped")
        self._stamp.set_text("Building")
        apply_eyebrow_style(self._status_label, "Building…")
        self._log_view.clear()

        self._worker = BuildWorker(argv, expected_exe, Path(save_to), self._tmp_root)
        self._worker.log.connect(self._on_log_line)
        self._worker.finished_ok.connect(self._on_finished)
        self._worker.failed.connect(self._on_failed)
        self._worker.start()

    def _cancel_build(self) -> None:
        if self._worker is not None:
            self._worker.cancel()

    def _on_log_line(self, line: str) -> None:
        self._log_view.appendPlainText(line)

    def _on_finished(self, saved_path: Path) -> None:
        self._saved_path = saved_path
        self._progress.setRange(0, 100)
        self._progress.setValue(100)
        self._build_button.setEnabled(True)
        self._cancel_button.setVisible(False)
        self._open_folder_button.setVisible(True)
        self._stamp.set_status("ok")
        self._stamp.set_text("Done")
        apply_eyebrow_style(self._status_label, f"Saved to {saved_path}")

    def _on_failed(self, message: str) -> None:
        self._progress.setRange(0, 100)
        self._progress.setValue(0)
        self._build_button.setEnabled(True)
        self._cancel_button.setVisible(False)
        self._stamp.set_status("error")
        self._stamp.set_text("Failed")
        apply_eyebrow_style(self._status_label, "Failed.")
        QMessageBox.critical(self, "Build failed", message)

    def _open_folder(self) -> None:
        if self._saved_path is not None:
            QDesktopServices.openUrl(QUrl.fromLocalFile(str(self._saved_path.parent)))
