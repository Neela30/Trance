"""Report tab: just displays report.html -- module-wise sections plus the summary are
already exactly what report.py + report_template.html.j2 render, so this is a viewer,
not a second implementation of the presentation logic."""

from __future__ import annotations

from pathlib import Path

from PySide6.QtCore import Qt, QUrl
from PySide6.QtWebEngineWidgets import QWebEngineView
from PySide6.QtWidgets import QLabel, QStackedWidget, QVBoxLayout, QWidget

from gui.theme import apply_eyebrow_style, apply_heading_style


class ReportTab(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self._view = QWebEngineView(self)

        placeholder_eyebrow = QLabel("Trance · Case Report", self)
        apply_eyebrow_style(placeholder_eyebrow)
        placeholder_eyebrow.setAlignment(Qt.AlignmentFlag.AlignCenter)
        placeholder_heading = QLabel("No report loaded yet", self)
        apply_heading_style(placeholder_heading)
        placeholder_heading.setAlignment(Qt.AlignmentFlag.AlignCenter)
        placeholder_note = QLabel("Run an analysis, or open one from History.", self)
        placeholder_note.setAlignment(Qt.AlignmentFlag.AlignCenter)
        placeholder_note.setStyleSheet("color: #8b969c;")

        self._placeholder = QWidget(self)
        placeholder_layout = QVBoxLayout(self._placeholder)
        placeholder_layout.addStretch(1)
        placeholder_layout.addWidget(placeholder_eyebrow)
        placeholder_layout.addWidget(placeholder_heading)
        placeholder_layout.addWidget(placeholder_note)
        placeholder_layout.addStretch(1)

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
