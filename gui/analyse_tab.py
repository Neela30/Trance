"""Analyse tab: pick an evidence folder, optionally set case name / targeting fields and
the advanced inputs (overrides, disk image or mounted volume, Volatility3), then run the
pipeline in a child process with a progress bar and a Cancel button. Resolves the folder
the same way analyze_evidence.py's CLI wrapper does -- analyze_evidence.resolve_evidence()
is reused as-is, no separate GUI-side path-discovery logic.

Run order when a disk image is to be mounted: MountSession (pkexec helper) mounts it,
the analysis runs with the mountpoint as disk_root, and the helper unmounts afterwards
-- on success, failure, cancel, or the app closing."""

from __future__ import annotations

import shutil
from pathlib import Path

from PySide6.QtCore import Qt, QTimer, Signal
from PySide6.QtWidgets import (
    QFileDialog,
    QFormLayout,
    QFrame,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPlainTextEdit,
    QProgressBar,
    QPushButton,
    QScrollArea,
    QStackedWidget,
    QVBoxLayout,
    QWidget,
)

from gui.advanced_inputs import DiskSection, InputsSection, MemorySection
from gui.analysis_request import AnalysisRequest, discovered_inputs, effective_inputs, validate
from gui.history import scan_history
from gui.processes import AnalysisProcess, MountSession, mount_support
from gui.theme import StatusIndicator, apply_eyebrow_style, apply_heading_style, repolish

FORM_MAX_WIDTH = 720
RUN_BUTTON_WIDTH = 240
RECENT_CASES_SHOWN = 3
PROGRESS_TICK_MS = 60
PROGRESS_STARTUP_TARGET = 6  # nominal early crawl before the first real checkpoint


class _EvidenceDropField(QLineEdit):
    """Read-only display field for the evidence folder -- populated by Browse… or by
    dropping a folder onto it. Read-only fields can still take keyboard focus by
    default in Qt, which otherwise leaves a permanent-looking focus ring on a field
    nothing ever types into; disabled here since Browse/drop are the only inputs."""

    folder_dropped = Signal(str)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setReadOnly(True)
        self.setFocusPolicy(Qt.FocusPolicy.NoFocus)
        self.setPlaceholderText("Drag a folder here, or click Browse…")
        self.setAcceptDrops(True)
        self.setProperty("empty", True)

    def dragEnterEvent(self, event) -> None:
        if self._local_dir_from(event.mimeData()) is not None:
            event.acceptProposedAction()

    def dropEvent(self, event) -> None:
        folder = self._local_dir_from(event.mimeData())
        if folder is not None:
            self.folder_dropped.emit(folder)
            event.acceptProposedAction()

    @staticmethod
    def _local_dir_from(mime_data) -> str | None:
        for url in mime_data.urls():
            if url.isLocalFile() and Path(url.toLocalFile()).is_dir():
                return url.toLocalFile()
        return None


class AnalyseTab(QWidget):
    analysis_finished = Signal(object)  # gui.analysis_runner.RunSummary

    def __init__(self, output_dir: Path, parent=None):
        super().__init__(parent)
        self._output_dir = output_dir
        self._request: AnalysisRequest | None = None
        self._case_dir_existed = False
        self._finish_state: tuple | None = None  # set when the analysis ends, shown after unmount

        self._analysis = AnalysisProcess(self)
        self._analysis.progress.connect(self._on_progress)
        self._analysis.log.connect(self._on_log_line)
        self._analysis.activity.connect(lambda text: apply_eyebrow_style(self._status_label, text))
        self._analysis.finished_ok.connect(self._on_finished)
        self._analysis.failed.connect(self._on_failed)
        self._analysis.cancelled.connect(self._on_cancelled)

        self._mount = MountSession(self)
        self._mount.mounted.connect(self._on_mounted)
        self._mount.failed.connect(self._on_mount_failed)
        self._mount.unmounted.connect(self._on_unmounted)
        self._mount_supported, self._mount_reason = mount_support()

        content = QWidget(self)
        content.setMaximumWidth(FORM_MAX_WIDTH)
        content_layout = QVBoxLayout(content)
        content_layout.setContentsMargins(0, 24, 0, 24)

        content_layout.addLayout(self._build_masthead())
        content_layout.addSpacing(16)
        content_layout.addWidget(self._build_fields_box())
        content_layout.addWidget(self._build_targeting_section())
        self._inputs_section = InputsSection(self)
        self._disk_section = DiskSection(self._mount_supported, self._mount_reason, self)
        self._memory_section = MemorySection(self)
        content_layout.addWidget(self._inputs_section)
        content_layout.addWidget(self._disk_section)
        content_layout.addWidget(self._memory_section)
        content_layout.addSpacing(4)
        content_layout.addLayout(self._build_run_row())
        content_layout.addSpacing(14)
        content_layout.addWidget(self._progress)
        content_layout.addWidget(self._status_label)
        content_layout.addSpacing(20)

        self._recent_cases_box = self._build_recent_cases_box()
        self._log_box = self._build_log_box()
        self._bottom_stack = QStackedWidget(self)
        self._bottom_stack.addWidget(self._recent_cases_box)
        self._bottom_stack.addWidget(self._log_box)
        content_layout.addWidget(self._bottom_stack)
        content_layout.addStretch(1)

        centered = QWidget(self)
        row = QHBoxLayout(centered)
        row.addStretch(1)
        row.addWidget(content)
        row.addStretch(1)
        scroll = QScrollArea(self)
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        scroll.setWidget(centered)
        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.addWidget(scroll)

        self.refresh_recent_cases()

    # -- construction -----------------------------------------------------------

    def _build_masthead(self) -> QHBoxLayout:
        eyebrow = QLabel("Trance", self)
        apply_eyebrow_style(eyebrow)
        heading = QLabel("Run a new analysis", self)
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

    def _build_fields_box(self) -> QGroupBox:
        evidence_label = QLabel("Evidence folder", self)
        apply_eyebrow_style(evidence_label)
        self._folder_field = _EvidenceDropField(self)
        self._folder_field.folder_dropped.connect(self._set_evidence_folder)
        browse_button = QPushButton("Browse…", self)
        browse_button.clicked.connect(self._browse)
        folder_row = QHBoxLayout()
        folder_row.addWidget(self._folder_field)
        folder_row.addWidget(browse_button)

        case_label = QLabel("Case name", self)
        apply_eyebrow_style(case_label)
        self._case_field = QLineEdit(self)
        case_help = QLabel(
            "Enter the report name. The evidence folder is optional when you only analyse "
            "a disk image or individually chosen inputs.",
            self,
        )
        case_help.setWordWrap(True)
        case_help.setStyleSheet("color: #8b969c; font-size: 11.5px;")

        fields_box = QGroupBox(self)
        fields_layout = QVBoxLayout()
        fields_layout.addWidget(evidence_label)
        fields_layout.addLayout(folder_row)
        fields_layout.addSpacing(10)
        fields_layout.addWidget(case_label)
        fields_layout.addWidget(self._case_field)
        fields_layout.addWidget(case_help)
        fields_box.setLayout(fields_layout)
        return fields_box

    def _build_targeting_section(self) -> QWidget:
        section = QWidget(self)
        section_layout = QVBoxLayout(section)
        section_layout.setContentsMargins(0, 10, 0, 0)

        self._targeting_toggle = QPushButton("+ Add targeting details", self)
        self._targeting_toggle.setProperty("class", "link")
        self._targeting_toggle.clicked.connect(self._toggle_targeting)
        section_layout.addWidget(self._targeting_toggle)

        self._onion_field = QLineEdit(self)
        self._host_field = QLineEdit(self)
        self._username_field = QLineEdit(self)
        self._onion_field.setPlaceholderText("e.g. sitename.onion")
        self._host_field.setPlaceholderText("e.g. 1.2.3.4:8080")
        self._username_field.setPlaceholderText("e.g. admin")

        self._targeting_box = QGroupBox(self)
        targeting_form = QFormLayout()
        targeting_form.addRow("Onion address", self._onion_field)
        targeting_form.addRow("Host[:port]", self._host_field)
        targeting_form.addRow("Username", self._username_field)
        self._targeting_box.setLayout(targeting_form)
        for label in (
            targeting_form.labelForField(self._onion_field),
            targeting_form.labelForField(self._host_field),
            targeting_form.labelForField(self._username_field),
        ):
            apply_eyebrow_style(label)
        self._targeting_box.setVisible(False)
        section_layout.addWidget(self._targeting_box)
        return section

    def _build_run_row(self) -> QHBoxLayout:
        self._run_button = QPushButton("Run analysis", self)
        self._run_button.setProperty("class", "primary")
        self._run_button.setFixedWidth(RUN_BUTTON_WIDTH)
        self._run_button.clicked.connect(self._run)

        self._progress = QProgressBar(self)
        self._progress.setRange(0, 100)
        self._progress.setValue(0)
        self._progress_target = 0
        self._progress_timer = QTimer(self)
        self._progress_timer.setInterval(PROGRESS_TICK_MS)
        self._progress_timer.timeout.connect(self._animate_progress)
        self._status_label = QLabel("", self)
        apply_eyebrow_style(self._status_label, "")

        run_row = QHBoxLayout()
        run_row.addStretch(1)
        run_row.addWidget(self._run_button)
        run_row.addStretch(1)
        return run_row

    def _build_recent_cases_box(self) -> QGroupBox:
        eyebrow = QLabel("Recent cases", self)
        apply_eyebrow_style(eyebrow)
        self._recent_cases_layout = QVBoxLayout()
        self._recent_cases_layout.addWidget(eyebrow)
        self._recent_cases_empty_label = QLabel("No analyses run yet.", self)
        self._recent_cases_empty_label.setStyleSheet("color: #8b969c;")
        self._recent_cases_layout.addWidget(self._recent_cases_empty_label)

        box = QGroupBox(self)
        box.setLayout(self._recent_cases_layout)
        return box

    def _build_log_box(self) -> QGroupBox:
        eyebrow = QLabel("Live log", self)
        apply_eyebrow_style(eyebrow)

        self._log_view = QPlainTextEdit(self)
        self._log_view.setReadOnly(True)
        self._log_view.setMaximumBlockCount(500)
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

    def _toggle_targeting(self) -> None:
        expanded = not self._targeting_box.isVisible()
        self._targeting_box.setVisible(expanded)
        self._targeting_toggle.setText(
            "− Hide targeting details" if expanded else "+ Add targeting details"
        )

    def _set_evidence_folder(self, folder: str) -> None:
        self._folder_field.setText(folder)
        self._folder_field.setProperty("empty", not folder)
        repolish(self._folder_field)
        if not self._case_field.text():
            self._case_field.setText(Path(folder).name)
        self._inputs_section.clear_overrides()
        try:
            self._inputs_section.set_discovered(discovered_inputs(folder))
        except (OSError, ValueError) as exc:  # unreadable/malformed acquire_manifest.json
            self._inputs_section.set_discovered({})
            QMessageBox.warning(self, "Evidence folder", f"Could not read the folder: {exc}")

    def _browse(self) -> None:
        folder = QFileDialog.getExistingDirectory(self, "Select evidence folder")
        if folder:
            self._set_evidence_folder(folder)

    def refresh_recent_cases(self) -> None:
        while self._recent_cases_layout.count() > 1:
            item = self._recent_cases_layout.takeAt(1)
            if item.widget():
                item.widget().deleteLater()

        recent = scan_history(self._output_dir)[:RECENT_CASES_SHOWN]
        if not recent:
            empty_label = QLabel("No analyses run yet.", self)
            empty_label.setStyleSheet("color: #8b969c;")
            self._recent_cases_layout.addWidget(empty_label)
            return

        for summary in recent:
            row = QLabel(
                f"{summary.case_name} — {summary.overall_status} — "
                f"{summary.generated_at or 'unknown time'}",
                self,
            )
            row.setStyleSheet("font-family: 'Cascadia Code', Consolas, monospace; font-size: 12px;")
            self._recent_cases_layout.addWidget(row)

    def _build_request(self) -> AnalysisRequest:
        evidence_dir = self._folder_field.text().strip() or None
        return AnalysisRequest(
            case_name=self._case_field.text().strip(),
            output_dir=str(self._output_dir),
            evidence_dir=evidence_dir,
            overrides=self._inputs_section.overrides(),
            onion=self._onion_field.text().strip(),
            host=self._host_field.text().strip(),
            username=self._username_field.text().strip(),
            **self._disk_section.values(),
            **self._memory_section.values(),
        )

    def _run(self) -> None:
        if self._analysis.is_running() or self._mount.is_active:
            self._cancel()
            return

        request = self._build_request()
        try:
            issues = validate(request, effective_inputs(request))
        except (OSError, ValueError) as exc:
            QMessageBox.warning(self, "Cannot start", f"Could not read the evidence: {exc}")
            return
        if issues.errors:
            QMessageBox.warning(self, "Cannot start", "\n\n".join(f"• {e}" for e in issues.errors))
            return

        self._request = request
        self._case_dir_existed = request.case_dir.exists()
        self._finish_state = None
        self._set_running_ui()
        for warning in issues.warnings:
            self._log_view.appendPlainText(f"[!] {warning}")

        if request.mount_image:
            apply_eyebrow_style(self._status_label, "Mounting disk image (administrator prompt)…")
            self._log_view.appendPlainText(f"[*] mounting {request.disk_image} read-only")
            self._mount.start(Path(request.disk_image))
        else:
            self._start_analysis()

    def _start_analysis(self) -> None:
        apply_eyebrow_style(self._status_label, "Starting…")
        self._analysis.start(self._request)

    def _cancel(self) -> None:
        self._run_button.setEnabled(False)
        apply_eyebrow_style(self._status_label, "Cancelling…")
        if self._analysis.is_running():
            self._analysis.cancel()
        elif self._mount.is_active:  # still waiting on the password prompt / mount
            self._finish_state = ("cancelled", None)
            self._mount.unmount()

    def shutdown(self) -> None:
        """Called when the window closes: stop the analysis, then unmount."""
        self._analysis.kill_and_wait()
        self._mount.unmount_and_wait()

    # -- mount session ---------------------------------------------------------

    def _on_mounted(self, event: dict) -> None:
        if self._finish_state is not None:  # cancelled while the password prompt was up
            self._mount.unmount()
            return
        self._log_view.appendPlainText(
            f"[*] mounted {event.get('partition')} ({event.get('format')}) "
            f"read-only at {event.get('mountpoint')}"
        )
        self._request.disk_root = event["mountpoint"]
        self._start_analysis()

    def _on_mount_failed(self, message: str) -> None:
        if self._finish_state == ("cancelled", None):
            self._show_cancelled()
            return
        self._finish_state = None
        self._reset_ui("error", "Failed", "Mount failed.")
        QMessageBox.critical(self, "Could not mount the disk image", message)

    def _on_unmounted(self, problems: list) -> None:
        self._log_view.appendPlainText("[*] disk image unmounted")
        for problem in problems:
            self._log_view.appendPlainText(f"[!] unmount: {problem}")
        self._show_finish_state()

    # -- analysis process --------------------------------------------------------

    def _end_analysis(self, state: tuple) -> None:
        """Record how the run ended; shown once the image (if any) is unmounted, so the
        UI never says 'Done' while the volume is still attached."""
        self._finish_state = state
        if self._mount.is_active:
            apply_eyebrow_style(self._status_label, "Unmounting disk image…")
            self._mount.unmount()
        else:
            self._show_finish_state()

    def _show_finish_state(self) -> None:
        state, self._finish_state = self._finish_state, None
        if state is None:
            return
        kind, payload = state
        if kind == "finished":
            self._progress_timer.stop()
            self._progress.setValue(100)
            self._reset_ui(
                "error" if payload.has_error else "ok",
                "Errors" if payload.has_error else "Done",
                "Done.",
            )
            self.refresh_recent_cases()
            self.analysis_finished.emit(payload)
        elif kind == "failed":
            self._reset_ui("error", "Failed", "Failed.")
            QMessageBox.critical(self, "Analysis failed", payload)
        else:
            self._show_cancelled()

    def _on_finished(self, summary) -> None:
        self._end_analysis(("finished", summary))

    def _on_failed(self, message: str) -> None:
        self._end_analysis(("failed", message))

    def _on_cancelled(self) -> None:
        self._end_analysis(("cancelled", None))

    def _show_cancelled(self) -> None:
        self._finish_state = None
        removed = ""
        if self._request and not self._case_dir_existed and self._request.case_dir.exists():
            shutil.rmtree(self._request.case_dir, ignore_errors=True)
            removed = " Partial case output removed."
        self._log_view.appendPlainText(f"[*] cancelled.{removed}")
        self._reset_ui("skipped", "Cancelled", f"Cancelled.{removed}")

    # -- ui state ----------------------------------------------------------------

    def _set_running_ui(self) -> None:
        self._run_button.setText("Cancel")
        self._run_button.setProperty("class", "danger")
        repolish(self._run_button)
        self._run_button.setEnabled(True)
        self._progress.setValue(0)
        self._progress_target = PROGRESS_STARTUP_TARGET
        self._progress_timer.start()
        self._stamp.set_status("skipped")
        self._stamp.set_text("Running")
        self._log_view.clear()
        self._bottom_stack.setCurrentWidget(self._log_box)

    def _reset_ui(self, status: str, stamp: str, message: str) -> None:
        self._progress_timer.stop()
        self._run_button.setText("Run analysis")
        self._run_button.setProperty("class", "primary")
        repolish(self._run_button)
        self._run_button.setEnabled(True)
        self._stamp.set_status(status)
        self._stamp.set_text(stamp)
        apply_eyebrow_style(self._status_label, message)
        if status == "ok":
            self._bottom_stack.setCurrentWidget(self._recent_cases_box)

    def _animate_progress(self) -> None:
        """Eases the displayed value toward the last confirmed checkpoint instead of
        snapping straight to it -- main.run_pipeline only reports 4 real checkpoints
        (3 modules + finalize), so this is a visual smoothing of those, not finer-
        grained data the pipeline doesn't actually have."""
        current = self._progress.value()
        if current >= self._progress_target:
            return
        step = max(1, int((self._progress_target - current) * 0.15))
        self._progress.setValue(min(self._progress_target, current + step))

    def _on_progress(self, name: str, step: int, total: int) -> None:
        self._progress_target = int(step / total * 100)
        apply_eyebrow_style(self._status_label, f"{name} ({step}/{total})")

    def _on_log_line(self, line: str) -> None:
        self._log_view.appendPlainText(line)
