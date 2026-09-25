"""Analyse tab: pick an evidence folder, optionally set case name / targeting fields,
run the pipeline in the background with a progress bar. Resolves the folder the same
way analyze_evidence.py's CLI wrapper does -- analyze_evidence.resolve_evidence() is
reused as-is, no separate GUI-side path-discovery logic."""

from __future__ import annotations

from pathlib import Path

from PySide6.QtCore import Signal
from PySide6.QtWidgets import (
    QFileDialog,
    QFormLayout,
    QGroupBox,
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
from gui.pipeline_inputs import module_kwargs_from_resolved
from gui.pipeline_worker import PipelineWorker


class AnalyseTab(QWidget):
    analysis_finished = Signal(object)  # main.PipelineResult

    def __init__(self, output_dir: Path, parent=None):
        super().__init__(parent)
        self._output_dir = output_dir
        self._worker: PipelineWorker | None = None

        self._folder_field = QLineEdit(self)
        self._folder_field.setReadOnly(True)
        browse_button = QPushButton("Browse…", self)
        browse_button.clicked.connect(self._browse)

        self._case_field = QLineEdit(self)
        self._onion_field = QLineEdit(self)
        self._host_field = QLineEdit(self)
        self._username_field = QLineEdit(self)

        form = QFormLayout()
        form.addRow("Evidence folder", browse_button)
        form.addRow("", self._folder_field)
        form.addRow("Case name", self._case_field)

        targeting_box = QGroupBox("Targeting (optional, needed for memory results)", self)
        targeting_form = QFormLayout()
        targeting_form.addRow("Onion address", self._onion_field)
        targeting_form.addRow("Host[:port]", self._host_field)
        targeting_form.addRow("Username", self._username_field)
        targeting_box.setLayout(targeting_form)

        self._run_button = QPushButton("Run analysis", self)
        self._run_button.clicked.connect(self._run)

        self._progress = QProgressBar(self)
        self._progress.setRange(0, 4)
        self._progress.setValue(0)
        self._status_label = QLabel("", self)

        layout = QVBoxLayout(self)
        layout.addLayout(form)
        layout.addWidget(targeting_box)
        layout.addWidget(self._run_button)
        layout.addWidget(self._progress)
        layout.addWidget(self._status_label)
        layout.addStretch(1)

    def _browse(self) -> None:
        folder = QFileDialog.getExistingDirectory(self, "Select evidence folder")
        if folder:
            self._folder_field.setText(folder)
            if not self._case_field.text():
                self._case_field.setText(Path(folder).name)

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
        self._status_label.setText("Starting…")

        self._worker = PipelineWorker(config, module_kwargs)
        self._worker.progress.connect(self._on_progress)
        self._worker.finished_ok.connect(self._on_finished)
        self._worker.failed.connect(self._on_failed)
        self._worker.start()

    def _on_progress(self, name: str, step: int, total: int) -> None:
        self._progress.setMaximum(total)
        self._progress.setValue(step)
        self._status_label.setText(f"{name} ({step}/{total})")

    def _on_finished(self, result: main.PipelineResult) -> None:
        self._run_button.setEnabled(True)
        self._status_label.setText("Done.")
        self.analysis_finished.emit(result)

    def _on_failed(self, message: str) -> None:
        self._run_button.setEnabled(True)
        self._status_label.setText("Failed.")
        QMessageBox.critical(self, "Analysis failed", message)
