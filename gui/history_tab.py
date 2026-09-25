"""History tab: lists past analyses by scanning <output-dir>/*/findings.json
(gui.history.scan_history) -- no separate store to keep in sync."""

from __future__ import annotations

from pathlib import Path

from PySide6.QtCore import QRect, Qt, Signal
from PySide6.QtGui import QColor, QFont, QPainter
from PySide6.QtWidgets import (
    QAbstractItemView,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QPushButton,
    QStyle,
    QStyledItemDelegate,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from gui.history import CaseSummary, format_relative_time, scan_history
from gui.theme import (
    COLORS,
    FONT_MONO,
    apply_eyebrow_style,
    apply_heading_style,
    status_bg_color,
    status_color,
)

_COLUMNS = ("Case", "Generated", "Status", "Artifacts")
_CASE_COLUMN, _GENERATED_COLUMN, _STATUS_COLUMN, _ARTIFACTS_COLUMN = range(4)


class _GeneratedItem(QTableWidgetItem):
    """QTableWidgetItem aliases Qt::DisplayRole and Qt::EditRole to the same storage
    slot (documented Qt behavior for the convenience item classes, not a quirk) -- so
    setting a relative-time display string and a separate ISO sort key via those two
    roles just silently collapses to whichever was set last. __lt__ is what
    sortItems() actually calls, so overriding it directly keeps sort correct (by the
    real timestamp) independent of whatever text is shown."""

    def __init__(self, iso_timestamp: str | None):
        super().__init__(format_relative_time(iso_timestamp))
        self._sort_key = iso_timestamp or ""
        self.setToolTip(iso_timestamp or "unknown")

    def __lt__(self, other: object) -> bool:
        if isinstance(other, _GeneratedItem):
            return self._sort_key < other._sort_key
        return super().__lt__(other)


class _StatusChipDelegate(QStyledItemDelegate):
    """Paints the Status column as a rounded chip (matching the report's .chip class)
    instead of a real child widget. QTableWidget's built-in sortItems() reorders
    QTableWidgetItems but does not relocate cell widgets set via setCellWidget(), so a
    delegate -- which paints per-index at render time -- is what lets this column stay
    both chip-styled and correctly sortable."""

    def paint(self, painter: QPainter, option, index) -> None:
        status = index.data(Qt.ItemDataRole.UserRole)
        if not status:
            super().paint(painter, option, index)
            return
        text = str(index.data(Qt.ItemDataRole.DisplayRole) or "")

        painter.save()
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)

        selected = bool(option.state & QStyle.StateFlag.State_Selected)
        painter.fillRect(
            option.rect, QColor(COLORS["accent_bg"] if selected else COLORS["surface"])
        )
        if selected:
            bar = QRect(option.rect.left(), option.rect.top(), 3, option.rect.height())
            painter.fillRect(bar, QColor(COLORS["accent"]))

        font = QFont(FONT_MONO)
        font.setPointSize(9)
        font.setLetterSpacing(QFont.SpacingType.PercentageSpacing, 106)
        painter.setFont(font)
        metrics = painter.fontMetrics()
        pad_x, pad_y = 10, 4
        chip_height = metrics.height() + pad_y * 2
        chip_width = metrics.horizontalAdvance(text) + pad_x * 2
        chip_rect = QRect(0, 0, chip_width, chip_height)
        chip_rect.moveLeft(option.rect.left() + 13)
        chip_rect.moveTop(option.rect.center().y() - chip_height // 2)

        painter.setPen(Qt.PenStyle.NoPen)
        painter.setBrush(QColor(status_bg_color(status)))
        painter.drawRoundedRect(chip_rect, chip_height // 2, chip_height // 2)
        painter.setPen(QColor(status_color(status)))
        painter.drawText(chip_rect, Qt.AlignmentFlag.AlignCenter, text)
        painter.restore()


class HistoryTab(QWidget):
    report_requested = Signal(Path)

    def __init__(self, output_dir: Path, parent=None):
        super().__init__(parent)
        self._output_dir = output_dir

        eyebrow = QLabel("Trance · Case Archive", self)
        apply_eyebrow_style(eyebrow)
        heading = QLabel("Past analyses", self)
        apply_heading_style(heading)

        self._filter_field = QLineEdit(self)
        self._filter_field.setPlaceholderText("Filter by case name…")
        self._filter_field.textChanged.connect(self._apply_filter)

        self._table = QTableWidget(0, len(_COLUMNS), self)
        self._table.setHorizontalHeaderLabels(_COLUMNS)
        self._table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self._table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self._table.horizontalHeader().setSectionResizeMode(
            _CASE_COLUMN, QHeaderView.ResizeMode.Stretch
        )
        self._table.horizontalHeader().setSortIndicatorShown(True)
        self._table.verticalHeader().setVisible(False)
        self._table.setItemDelegateForColumn(_STATUS_COLUMN, _StatusChipDelegate(self._table))
        self._table.doubleClicked.connect(self._open_selected_report)
        self._table.itemSelectionChanged.connect(self._update_open_button_state)

        refresh_button = QPushButton("⟳  Refresh", self)
        refresh_button.clicked.connect(self.refresh)
        self._open_button = QPushButton("View report", self)
        self._open_button.setProperty("class", "primary")
        self._open_button.setEnabled(False)
        self._open_button.clicked.connect(self._open_selected_report)

        button_row = QHBoxLayout()
        button_row.addWidget(refresh_button)
        button_row.addWidget(self._open_button)
        button_row.addStretch(1)

        self._footer_label = QLabel("", self)
        self._footer_label.setStyleSheet("color: #8b969c; font-size: 11.5px;")

        layout = QVBoxLayout(self)
        layout.addWidget(eyebrow)
        layout.addWidget(heading)
        layout.addSpacing(12)
        layout.addLayout(button_row)
        layout.addWidget(self._filter_field)
        layout.addWidget(self._table, 1)
        layout.addWidget(self._footer_label)

        self.refresh()

    def refresh(self) -> None:
        self._table.setSortingEnabled(False)  # avoid a re-sort mid-population
        summaries = scan_history(self._output_dir)
        self._table.setRowCount(len(summaries))
        for row, summary in enumerate(summaries):
            self._table.setItem(row, _CASE_COLUMN, self._case_item(summary))
            self._table.setItem(row, _GENERATED_COLUMN, self._generated_item(summary))
            self._table.setItem(row, _STATUS_COLUMN, self._status_item(summary))
            self._table.setItem(row, _ARTIFACTS_COLUMN, self._artifacts_item(summary))
        self._table.setSortingEnabled(True)
        self._footer_label.setText(f"{len(summaries)} case{'s' if len(summaries) != 1 else ''}")
        self._apply_filter(self._filter_field.text())
        self._update_open_button_state()

    @staticmethod
    def _case_item(summary: CaseSummary) -> QTableWidgetItem:
        item = QTableWidgetItem(summary.case_name)
        # carries the summary itself so row lookups survive sortItems() reordering --
        # a plain row-index into a parallel Python list would not.
        item.setData(Qt.ItemDataRole.UserRole, summary)
        return item

    @staticmethod
    def _generated_item(summary: CaseSummary) -> QTableWidgetItem:
        return _GeneratedItem(summary.generated_at)

    @staticmethod
    def _status_item(summary: CaseSummary) -> QTableWidgetItem:
        item = QTableWidgetItem()
        item.setData(Qt.ItemDataRole.DisplayRole, summary.overall_status.upper())
        item.setData(Qt.ItemDataRole.UserRole, summary.overall_status)
        return item

    @staticmethod
    def _artifacts_item(summary: CaseSummary) -> QTableWidgetItem:
        item = QTableWidgetItem()
        item.setData(Qt.ItemDataRole.DisplayRole, str(summary.artifact_count))
        item.setData(Qt.ItemDataRole.EditRole, summary.artifact_count)  # numeric, not string, sort
        return item

    def _apply_filter(self, text: str) -> None:
        needle = text.strip().lower()
        for row in range(self._table.rowCount()):
            case_item = self._table.item(row, _CASE_COLUMN)
            match = needle in case_item.text().lower() if case_item else False
            self._table.setRowHidden(row, bool(needle) and not match)

    def _update_open_button_state(self) -> None:
        self._open_button.setEnabled(bool(self._table.selectedItems()))

    def _open_selected_report(self) -> None:
        row = self._table.currentRow()
        if row < 0:
            return
        case_item = self._table.item(row, _CASE_COLUMN)
        if case_item is None:
            return
        summary: CaseSummary = case_item.data(Qt.ItemDataRole.UserRole)
        if summary is not None and summary.report_path is not None:
            self.report_requested.emit(summary.report_path)
