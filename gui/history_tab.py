"""History tab: lists past analyses by scanning <output-dir>/*/findings.json
(gui.history.scan_history) -- no separate store to keep in sync."""

from __future__ import annotations

from pathlib import Path

from PySide6.QtCore import Signal
from PySide6.QtWidgets import (
    QAbstractItemView,
    QHBoxLayout,
    QHeaderView,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from gui.history import CaseSummary, scan_history

_COLUMNS = ("Case", "Generated", "Status", "Artifacts")


class HistoryTab(QWidget):
    report_requested = Signal(Path)

    def __init__(self, output_dir: Path, parent=None):
        super().__init__(parent)
        self._output_dir = output_dir
        self._summaries: list[CaseSummary] = []

        self._table = QTableWidget(0, len(_COLUMNS), self)
        self._table.setHorizontalHeaderLabels(_COLUMNS)
        self._table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self._table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self._table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        self._table.doubleClicked.connect(self._open_selected_report)

        refresh_button = QPushButton("Refresh", self)
        refresh_button.clicked.connect(self.refresh)
        open_button = QPushButton("View report", self)
        open_button.clicked.connect(self._open_selected_report)

        button_row = QHBoxLayout()
        button_row.addWidget(refresh_button)
        button_row.addWidget(open_button)
        button_row.addStretch(1)

        layout = QVBoxLayout(self)
        layout.addLayout(button_row)
        layout.addWidget(self._table)

        self.refresh()

    def refresh(self) -> None:
        self._summaries = scan_history(self._output_dir)
        self._table.setRowCount(len(self._summaries))
        for row, summary in enumerate(self._summaries):
            self._table.setItem(row, 0, QTableWidgetItem(summary.case_name))
            self._table.setItem(row, 1, QTableWidgetItem(summary.generated_at or "—"))
            self._table.setItem(row, 2, QTableWidgetItem(summary.overall_status))
            self._table.setItem(row, 3, QTableWidgetItem(str(summary.artifact_count)))

    def _open_selected_report(self) -> None:
        row = self._table.currentRow()
        if row < 0 or row >= len(self._summaries):
            return
        report_path = self._summaries[row].report_path
        if report_path is not None:
            self.report_requested.emit(report_path)
