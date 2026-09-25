"""Design tokens + helpers for the app's Qt theme, matching report_template.html.j2's
CSS custom properties (dark theme) so the native UI and the embedded report read as one
system. Qt Style Sheets (theme.qss) cover color/border/radius/font-family/state -- Qt
Style Sheets have no text-transform or letter-spacing support, so the report's eyebrow-
label letter-spacing is set directly on QFont here instead.
"""

from __future__ import annotations

from pathlib import Path

from PySide6.QtCore import Qt
from PySide6.QtGui import QFont
from PySide6.QtWidgets import QHBoxLayout, QLabel, QWidget

COLORS = {
    "bg": "#14181b",
    "surface": "#1b2126",
    "surface_2": "#232a2f",
    "ink": "#dce2e6",
    "ink_muted": "#8b969c",
    "border": "#313a40",
    "accent": "#e2694f",
    "accent_bg": "#33211c",
    "confirm": "#4fae84",
    "confirm_bg": "#1e2e27",
    "noise": "#c9a552",
    "noise_bg": "#2c2818",
    "mono_chip_bg": "#232a2f",
}

FONT_MONO = "Cascadia Code"
FONT_SERIF = "Georgia"

_QSS_PATH = Path(__file__).parent / "theme.qss"


def load_stylesheet() -> str:
    return _QSS_PATH.read_text()


def apply_eyebrow_style(label: QLabel, text: str | None = None) -> None:
    """Small uppercase monospace muted label, matching the report's .eyebrow class --
    letter-spacing has no QSS equivalent, so it's set on the QFont directly."""
    label.setText((text if text is not None else label.text()).upper())
    label.setProperty("class", "eyebrow")
    font = QFont(FONT_MONO)
    font.setPointSize(9)
    font.setLetterSpacing(QFont.SpacingType.PercentageSpacing, 114)  # ~0.14em
    label.setFont(font)
    repolish(label)


def apply_heading_style(label: QLabel) -> None:
    """Serif section heading, matching the report's h1/h2 -- the "official report" feel
    instead of the platform's default UI font."""
    label.setProperty("class", "heading")
    font = QFont(FONT_SERIF)
    font.setPointSize(16)
    font.setWeight(QFont.Weight.DemiBold)
    label.setFont(font)
    repolish(label)


def status_color(status: str) -> str:
    return {"ok": COLORS["confirm"], "error": COLORS["accent"]}.get(status, COLORS["noise"])


def status_bg_color(status: str) -> str:
    return {"ok": COLORS["confirm_bg"], "error": COLORS["accent_bg"]}.get(
        status, COLORS["noise_bg"]
    )


def repolish(widget: QWidget) -> None:
    """Force Qt to re-evaluate QSS after a dynamic property (setProperty) changes --
    Qt caches a widget's style computation, so a property change alone doesn't repaint
    with the new selector match until unpolish/polish runs."""
    style = widget.style()
    style.unpolish(widget)
    style.polish(widget)


class StatusIndicator(QWidget):
    """Horizontal status pill: a small filled dot + label text (e.g. Ready/Running/
    Done/Errors on the Analyse tab) -- plain and legible rather than a report-style
    rotated stamp, which reads oddly for something meant to update live."""

    _DOT_SIZE = 10

    def __init__(self, text: str = "", parent=None):
        super().__init__(parent)
        self._dot = QWidget(self)
        self._dot.setFixedSize(self._DOT_SIZE, self._DOT_SIZE)
        self._dot.setAttribute(Qt.WidgetAttribute.WA_StyledBackground, True)

        self._label = QLabel(text.upper(), self)
        font = QFont(FONT_MONO)
        font.setPointSize(10)
        font.setLetterSpacing(QFont.SpacingType.PercentageSpacing, 108)
        self._label.setFont(font)

        layout = QHBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(8)
        layout.addWidget(self._dot)
        layout.addWidget(self._label)

        self.set_status("skipped")

    def set_text(self, text: str) -> None:
        self._label.setText(text.upper())

    def set_status(self, status: str) -> None:
        color = status_color(status)
        self._dot.setStyleSheet(f"background: {color}; border-radius: {self._DOT_SIZE // 2}px;")
        self._label.setStyleSheet(f"color: {color};")
