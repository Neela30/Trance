"""Report tab: just displays report.html -- module-wise sections plus the summary are
already exactly what report.py + report_template.html.j2 render, so this is a viewer,
not a second implementation of the presentation logic.

The report is built from untrusted evidence, so the view is locked down (gui.report_policy):
JavaScript off, no network or other-file access from the local page, the default
off-the-record profile with downloads refused, and navigation limited to the report itself."""

from __future__ import annotations

from pathlib import Path

from PySide6.QtCore import QMarginsF, Qt, QUrl
from PySide6.QtGui import QPageLayout, QPageSize
from PySide6.QtWebEngineCore import QWebEnginePage, QWebEngineProfile, QWebEngineSettings
from PySide6.QtWebEngineWidgets import QWebEngineView
from PySide6.QtWidgets import (
    QFileDialog,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QStackedWidget,
    QVBoxLayout,
    QWidget,
)

from gui.pdf_export import (
    OPEN_ALL_DETAILS_JS,
    RESTORE_DETAILS_JS,
    default_pdf_path,
    record_pdf_export,
)
from gui.report_policy import WEB_ATTRIBUTES, navigation_allowed
from gui.theme import apply_eyebrow_style, apply_heading_style
from report import EXHIBIT_LIST_FILENAME


class _ReportPage(QWebEnginePage):
    """Only ever shows the one report it was given; every other navigation is refused."""

    def __init__(self, parent=None):
        # Qt 6's default profile is off-the-record: nothing is written to disk.
        profile = QWebEngineProfile.defaultProfile()
        super().__init__(profile, parent)
        profile.downloadRequested.connect(lambda item: item.cancel())
        settings = self.settings()
        for name, value in WEB_ATTRIBUTES.items():
            settings.setAttribute(getattr(QWebEngineSettings.WebAttribute, name), value)
        self.report_path: Path | None = None

    def acceptNavigationRequest(self, url, _type, _is_main_frame) -> bool:
        return navigation_allowed(url.toString(), self.report_path)

    def createWindow(self, _type):
        return None  # no pop-ups or "open in new window"


class ReportTab(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self._view = QWebEngineView(self)
        self._page = _ReportPage(self._view)
        self._view.setPage(self._page)

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

        self._pdf_button = QPushButton("Save as PDF…", self)
        self._pdf_button.setEnabled(False)
        self._pdf_button.setToolTip(
            "Save the report as an A4 PDF with every section expanded, the case and page "
            "number on each page, and findings.json's SHA-256 in each page footer. The PDF's "
            "own hash is added to the case's custody.json."
        )
        self._pdf_button.clicked.connect(self._save_pdf)
        self._exhibits_button = QPushButton("Exhibit list", self)
        self._exhibits_button.setVisible(False)
        self._exhibits_button.setToolTip(
            "Switch to the one-page list of the evidence (exhibit numbers, files, SHA-256) "
            "for filing with the court; Save as PDF then saves that page."
        )
        self._exhibits_button.clicked.connect(self._toggle_exhibit_list)
        self._pdf_status = QLabel("", self)
        self._pdf_status.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        self._pdf_status.setStyleSheet("color: #8b969c;")
        toolbar = QHBoxLayout()
        toolbar.addWidget(self._pdf_status, 1)
        toolbar.addWidget(self._exhibits_button)
        toolbar.addWidget(self._pdf_button)

        layout = QVBoxLayout(self)
        layout.addLayout(toolbar)
        layout.addWidget(self._stack)

        self._current_report_path: Path | None = None
        self._report_html: Path | None = None  # report.html of the case on screen
        self._pending_pdf: Path | None = None
        self._view.loadFinished.connect(self._on_load_finished)
        self._view.page().pdfPrintingFinished.connect(self._on_pdf_finished)

    def load_report(self, report_path: Path) -> None:
        self._report_html = Path(report_path).resolve()
        self._show(self._report_html)

    def _toggle_exhibit_list(self) -> None:
        if self._report_html is None:
            return
        exhibits = self._report_html.with_name(EXHIBIT_LIST_FILENAME)
        self._show(self._report_html if self._current_report_path == exhibits else exhibits)

    def _show(self, page_path: Path) -> None:
        # QUrl.fromLocalFile needs an absolute path -- report_path can be relative when
        # --output-dir was given as one (e.g. the "output" default), which otherwise
        # produces a malformed file:// URL and ERR_FILE_NOT_FOUND.
        self._current_report_path = Path(page_path).resolve()
        showing_exhibits = self._current_report_path.name == EXHIBIT_LIST_FILENAME
        self._exhibits_button.setText("Full report" if showing_exhibits else "Exhibit list")
        self._exhibits_button.setVisible(
            self._report_html is not None
            and self._report_html.with_name(EXHIBIT_LIST_FILENAME).is_file()
        )
        self._page.report_path = self._current_report_path
        self._pdf_button.setEnabled(False)
        self._pdf_status.setText("")
        self._view.load(QUrl.fromLocalFile(str(self._current_report_path)))
        self._stack.setCurrentWidget(self._view)

    def _on_load_finished(self, ok: bool) -> None:
        self._pdf_button.setEnabled(ok and self._current_report_path is not None)

    def _save_pdf(self) -> None:
        if self._current_report_path is None:
            return
        chosen, _ = QFileDialog.getSaveFileName(
            self,
            "Save report as PDF",
            str(default_pdf_path(self._current_report_path)),
            "PDF files (*.pdf)",
        )
        if not chosen:
            return
        path = Path(chosen)
        if path.suffix.lower() != ".pdf":
            path = path.with_suffix(".pdf")
        self._pending_pdf = path
        self._pdf_button.setEnabled(False)
        self._pdf_status.setText("Saving PDF…")
        # Same as report_template.html.j2's @page rule: Qt's margins win over the CSS ones,
        # and the page header/footer (case, page number, findings hash) print inside them.
        layout = QPageLayout(
            QPageSize(QPageSize.PageSizeId.A4),
            QPageLayout.Orientation.Portrait,
            QMarginsF(14, 18, 14, 20),
            QPageLayout.Unit.Millimeter,
        )
        self._view.page().runJavaScript(
            OPEN_ALL_DETAILS_JS,
            0,
            lambda _result: self._view.page().printToPdf(str(path), layout),
        )

    def _on_pdf_finished(self, file_path: str, success: bool) -> None:
        self._view.page().runJavaScript(RESTORE_DETAILS_JS)
        self._pdf_button.setEnabled(self._current_report_path is not None)
        pending, self._pending_pdf = self._pending_pdf, None
        if not success or pending is None or self._current_report_path is None:
            self._pdf_status.setText(f"Could not save the PDF to {file_path}.")
            return
        try:
            digest = record_pdf_export(self._current_report_path, Path(file_path))
        except OSError as exc:
            self._pdf_status.setText(f"Saved {file_path}, but custody.json was not updated: {exc}")
            return
        self._pdf_status.setText(f"Saved {file_path} · SHA-256 {digest} (recorded in custody.json)")

    def clear_if_showing(self, case_dir: Path) -> None:
        """Reset to the empty state if the report currently on screen belonged to
        case_dir -- called after a History deletion so a stale, now-nonexistent report
        doesn't sit there looking current."""
        if (
            self._current_report_path is not None
            and case_dir.resolve() in self._current_report_path.parents
        ):
            self._current_report_path = self._report_html = None
            self._exhibits_button.setVisible(False)
            self._pdf_button.setEnabled(False)
            self._pdf_status.setText("")
            self._stack.setCurrentWidget(self._placeholder)
