"""Analyse tab: pick an evidence folder, optionally set case name / targeting fields,
run the pipeline in the background with a progress bar. Resolves the folder the same
way analyze_evidence.py's CLI wrapper does -- analyze_evidence.resolve_evidence() is
reused as-is, no separate GUI-side path-discovery logic."""

from __future__ import annotations

from pathlib import Path

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QFileDialog,
    QFormLayout,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QProgressBar,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

import main
from analyze_evidence import resolve_evidence
from core.config import TranceConfig
from gui.history import scan_history
from gui.pipeline_inputs import module_kwargs_from_resolved
from gui.pipeline_worker import PipelineWorker
from gui.theme import StatusIndicator, apply_eyebrow_style, apply_heading_style, repolish

FORM_MAX_WIDTH = 720
RUN_BUTTON_WIDTH = 240
RECENT_CASES_SHOWN = 3


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
    analysis_finished = Signal(object)  # main.PipelineResult

    def __init__(self, output_dir: Path, parent=None):
        super().__init__(parent)
        self._output_dir = output_dir
        self._worker: PipelineWorker | None = None

        content = QWidget(self)
        content.setMaximumWidth(FORM_MAX_WIDTH)
        content_layout = QVBoxLayout(content)
        content_layout.setContentsMargins(0, 24, 0, 24)

        content_layout.addLayout(self._build_masthead())
        content_layout.addSpacing(16)
        content_layout.addWidget(self._build_fields_box())
        content_layout.addWidget(self._build_targeting_section())
        content_layout.addSpacing(4)
        content_layout.addLayout(self._build_run_row())
        content_layout.addSpacing(14)
        content_layout.addWidget(self._progress)
        content_layout.addWidget(self._status_label)
        content_layout.addSpacing(20)
        content_layout.addWidget(self._build_recent_cases_box())
        content_layout.addStretch(1)

        outer = QHBoxLayout(self)
        outer.addStretch(1)
        outer.addWidget(content)
        outer.addStretch(1)

        self._refresh_recent_cases()

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
        case_help = QLabel("Enter the report name", self)
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
        self._progress.setRange(0, 4)
        self._progress.setValue(0)
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

    def _browse(self) -> None:
        folder = QFileDialog.getExistingDirectory(self, "Select evidence folder")
        if folder:
            self._set_evidence_folder(folder)

    def _refresh_recent_cases(self) -> None:
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

    def _run(self) -> None:
        evidence_dir = self._folder_field.text().strip()
        case_name = self._case_field.text().strip()
        if not evidence_dir:
            QMessageBox.warning(self, "Missing folder", "Pick an evidence folder first.")
            return
        if not case_name or Path(case_name).name != case_name or case_name in (".", ".."):
            QMessageBox.warning(
                self,
                "Invalid case name",
                "Case name must be a single folder name, no path separators.",
            )
            return

        case_output_dir = self._output_dir / case_name
        for existing in ("findings.json", "report.html", main.CUSTODY_FILENAME):
            if (case_output_dir / existing).exists():
                QMessageBox.warning(
                    self,
                    "Case already exists",
                    f"Outputs already exist, pick a new case name: {case_output_dir}",
                )
                return

        resolved = resolve_evidence(Path(evidence_dir))
        module_kwargs = module_kwargs_from_resolved(
            resolved,
            self._onion_field.text().strip(),
            self._host_field.text().strip(),
            self._username_field.text().strip(),
        )

        case_output_dir.mkdir(parents=True, exist_ok=True)
        config = TranceConfig(
            case_name=case_name, output_dir=case_output_dir, evidence_dir=Path(evidence_dir)
        )

        self._run_button.setEnabled(False)
        self._progress.setValue(0)
        self._stamp.set_status("skipped")
        self._stamp.set_text("Running")
        apply_eyebrow_style(self._status_label, "Starting…")

        self._worker = PipelineWorker(config, module_kwargs)
        self._worker.progress.connect(self._on_progress)
        self._worker.finished_ok.connect(self._on_finished)
        self._worker.failed.connect(self._on_failed)
        self._worker.start()

    def _on_progress(self, name: str, step: int, total: int) -> None:
        self._progress.setMaximum(total)
        self._progress.setValue(step)
        apply_eyebrow_style(self._status_label, f"{name} ({step}/{total})")

    def _on_finished(self, result: main.PipelineResult) -> None:
        self._run_button.setEnabled(True)
        self._stamp.set_status("error" if result.has_error else "ok")
        self._stamp.set_text("Errors" if result.has_error else "Done")
        apply_eyebrow_style(self._status_label, "Done.")
        self._refresh_recent_cases()
        self.analysis_finished.emit(result)

    def _on_failed(self, message: str) -> None:
        self._run_button.setEnabled(True)
        self._stamp.set_status("error")
        self._stamp.set_text("Failed")
        apply_eyebrow_style(self._status_label, "Failed.")
        QMessageBox.critical(self, "Analysis failed", message)
