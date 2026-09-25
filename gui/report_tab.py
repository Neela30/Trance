"""Report tab: just displays report.html -- module-wise sections plus the summary are
already exactly what report.py + report_template.html.j2 render, so this is a viewer,
not a second implementation of the presentation logic."""

from __future__ import annotations

from pathlib import Path

from PySide6.QtCore import Qt, QUrl
from PySide6.QtWebEngineWidgets import QWebEngineView
from PySide6.QtWidgets import QLabel, QStackedWidget, QVBoxLayout, QWidget


class ReportTab(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self._view = QWebEngineView(self)
        self._placeholder = QLabel(
            "No report loaded yet. Run an analysis, or open one from History.", self
        )
        self._placeholder.setAlignment(Qt.AlignmentFlag.AlignCenter)

        self._stack = QStackedWidget(self)
        self._stack.addWidget(self._placeholder)
        self._stack.addWidget(self._view)

        layout = QVBoxLayout(self)
        layout.addWidget(self._stack)

    def load_report(self, report_path: Path) -> None:
        self._view.load(QUrl.fromLocalFile(str(report_path)))
        self._stack.setCurrentWidget(self._view)
