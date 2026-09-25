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
        # QUrl.fromLocalFile needs an absolute path -- report_path can be relative when
        # --output-dir was given as one (e.g. the "output" default), which otherwise
        # produces a malformed file:// URL and ERR_FILE_NOT_FOUND.
        self._view.load(QUrl.fromLocalFile(str(Path(report_path).resolve())))
        self._stack.setCurrentWidget(self._view)
