from __future__ import annotations

from pathlib import Path

from PySide6.QtWidgets import QMainWindow, QTabWidget

from gui.analyse_tab import AnalyseTab
from gui.history_tab import HistoryTab
from gui.report_tab import ReportTab


class MainWindow(QMainWindow):
    def __init__(self, output_dir: Path = Path("output"), parent=None):
        super().__init__(parent)
        self.setWindowTitle("TRANCE")
        self.resize(1000, 700)

        self._analyse_tab = AnalyseTab(output_dir, self)
        self._report_tab = ReportTab(self)
        self._history_tab = HistoryTab(output_dir, self)

        self._tabs = QTabWidget(self)
        self._tabs.addTab(self._analyse_tab, "Analyse")
        self._tabs.addTab(self._report_tab, "Report")
        self._tabs.addTab(self._history_tab, "History")
        self.setCentralWidget(self._tabs)

        self._analyse_tab.analysis_finished.connect(self._on_analysis_finished)
        self._history_tab.report_requested.connect(self._on_report_requested)
        self._history_tab.case_deleted.connect(self._on_case_deleted)

    def _on_analysis_finished(self, result) -> None:
        self._report_tab.load_report(result.report_path)
        self._tabs.setCurrentWidget(self._report_tab)
        self._history_tab.refresh()

    def _on_report_requested(self, report_path: Path) -> None:
        self._report_tab.load_report(report_path)
        self._tabs.setCurrentWidget(self._report_tab)

    def _on_case_deleted(self, case_dir: Path) -> None:
        self._report_tab.clear_if_showing(case_dir)
        self._analyse_tab.refresh_recent_cases()
