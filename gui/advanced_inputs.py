"""The Analyse tab's building blocks beyond folder + case name:

  EvidenceSummary  the "Evidence found" checklist -- what this run will analyse
  OptionsPanel     one "More options" toggle over a tabbed card:
                     Target  host / username (the onion lives on the main card)
                     Inputs  each auto-discovered input, overridable (main.py's
                             --system/--ntuser/--amcache/--dump/--disk-profile/
                             --tor-dir/--downloads-scan)
                     Disk    none / an image file (mount and/or byte search) /
                             an already-mounted volume (--disk-image, --disk-root)
                     Memory  --source-type and the Volatility3 options

Spacing constants are deliberately generous: every label sits clear of its field and
every help line clear of the next control, so the form reads as steps, not a wall."""

from __future__ import annotations

import shutil
from pathlib import Path

from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QIntValidator
from PySide6.QtWidgets import (
    QButtonGroup,
    QCheckBox,
    QComboBox,
    QFileDialog,
    QGridLayout,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QRadioButton,
    QSizePolicy,
    QStackedWidget,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

from gui.analysis_request import INPUT_SPECS, SummaryRow, display_path
from gui.theme import COLORS, apply_eyebrow_style

# Breathing room, in px -- used consistently across the tab.
FIELD_GAP = 8  # label -> its field
ROW_GAP = 14  # between label/field groups
SECTION_GAP = 22  # between blocks inside a card
CARD_MARGINS = (20, 4, 20, 20)  # theme.qss already pads a QGroupBox's top
CHECK_INDENT = 26  # aligns help text under a checkbox with the checkbox's label

IMAGE_FILTER = (
    "Disk images (*.vdi *.vmdk *.vhd *.vhdx *.qcow2 *.raw *.img *.dd *.001);;All files (*)"
)
SOURCE_TYPE_CHOICES = (
    ("Detect automatically", None),
    ("Live browser process dump (firefox_*.bin)", "process"),
    ("Full memory image (WinPMEM or VM snapshot)", "full-memory"),
)
DOT_COLORS = {"found": COLORS["confirm"], "missing": COLORS["ink_muted"], "off": COLORS["border"]}


def help_label(text: str, parent: QWidget) -> QLabel:
    label = QLabel(text, parent)
    label.setWordWrap(True)
    label.setStyleSheet(f"color: {COLORS['ink_muted']}; font-size: 12px; padding-top: 2px;")
    return label


def field_label(text: str, parent: QWidget) -> QLabel:
    label = QLabel(text, parent)
    apply_eyebrow_style(label)
    return label


def labelled(label: QWidget, field, help_text: str | None = None, parent=None) -> QVBoxLayout:
    """label / field / optional help, with the same gaps everywhere."""
    box = QVBoxLayout()
    box.setSpacing(FIELD_GAP)
    box.addWidget(label)
    if isinstance(field, QWidget):
        box.addWidget(field)
    else:
        box.addLayout(field)
    if help_text:
        box.addWidget(help_label(help_text, parent))
    return box


def option(checkbox: QCheckBox, help_text: str, parent: QWidget) -> QVBoxLayout:
    """A checkbox with its explanation underneath, lined up with the checkbox's text."""
    box = QVBoxLayout()
    box.setSpacing(4)
    box.addWidget(checkbox)
    explanation = help_label(help_text, parent)
    explanation.setContentsMargins(CHECK_INDENT, 0, 0, 0)
    box.addWidget(explanation)
    return box


def card(parent: QWidget) -> tuple[QGroupBox, QVBoxLayout]:
    box = QGroupBox(parent)
    layout = QVBoxLayout(box)
    layout.setContentsMargins(*CARD_MARGINS)
    layout.setSpacing(ROW_GAP)
    return box, layout


class _Dot(QLabel):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setFixedSize(9, 9)
        self.set_state("off")

    def set_state(self, state: str) -> None:
        self.setStyleSheet(f"background: {DOT_COLORS[state]}; border-radius: 4px;")


class PathLabel(QLabel):
    """A path shown like a read-only field, shortened in the middle so both the start
    and the file name stay visible; the full path is in the tooltip."""

    def __init__(self, placeholder: str, parent=None):
        super().__init__(parent)
        self._full = ""
        self._shown = ""
        self._placeholder = placeholder
        self.setMinimumWidth(120)
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Preferred)
        self.set_path("")

    def set_path(self, full: str, shown: str | None = None) -> None:
        self._full = full
        self._shown = shown if shown is not None else full
        self.setToolTip(full)
        self._render()

    def path(self) -> str:
        return self._full

    def resizeEvent(self, event) -> None:
        super().resizeEvent(event)
        self._render()

    def _render(self) -> None:
        color = COLORS["ink"] if self._full else COLORS["ink_muted"]
        self.setStyleSheet(
            f"background: {COLORS['surface_2']}; border: 1px solid {COLORS['border']}; "
            f"border-radius: 6px; padding: 8px 10px; color: {color};"
        )
        if not self._full:
            self.setText(self._placeholder)
            return
        width = max(40, self.width() - 24)
        self.setText(
            self.fontMetrics().elidedText(self._shown, Qt.TextElideMode.ElideMiddle, width)
        )


class PathPicker(QWidget):
    """PathLabel + Browse… + Clear (Clear only shown when there's something to clear)."""

    changed = Signal()

    def __init__(self, placeholder: str, is_dir: bool, file_filter: str = "", parent=None):
        super().__init__(parent)
        self._is_dir = is_dir
        self._filter = file_filter
        self.label = PathLabel(placeholder, self)
        browse = QPushButton("Browse…", self)
        browse.clicked.connect(self._browse)
        self._clear = QPushButton("Clear", self)
        self._clear.clicked.connect(lambda: self.set_path(""))
        row = QHBoxLayout(self)
        row.setContentsMargins(0, 0, 0, 0)
        row.setSpacing(FIELD_GAP)
        row.addWidget(self.label, 1)
        row.addWidget(browse)
        row.addWidget(self._clear)
        self._clear.setVisible(False)

    def path(self) -> str:
        return self.label.path()

    def set_path(self, value: str) -> None:
        self.label.set_path(value)
        self._clear.setVisible(bool(value))
        self.changed.emit()

    def _browse(self) -> None:
        start = self.path() or str(Path.home())
        if self._is_dir:
            chosen = QFileDialog.getExistingDirectory(self, "Select folder", start)
        else:
            chosen, _ = QFileDialog.getOpenFileName(self, "Select file", start, self._filter)
        if chosen:
            self.set_path(chosen)


class EvidenceSummary(QGroupBox):
    """'Evidence found': one line per kind of evidence with a status dot."""

    def __init__(self, parent=None):
        super().__init__(parent)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(*CARD_MARGINS)
        layout.setSpacing(ROW_GAP)
        layout.addWidget(field_label("Evidence found", self))
        self._empty = help_label("Pick an evidence folder to see what will be analysed.", self)
        layout.addWidget(self._empty)
        self._grid = QGridLayout()
        self._grid.setHorizontalSpacing(14)
        self._grid.setVerticalSpacing(12)
        self._grid.setColumnStretch(2, 1)
        layout.addLayout(self._grid)
        self._widgets: list[QWidget] = []

    def set_rows(self, rows: list[SummaryRow], has_source: bool) -> None:
        for widget in self._widgets:
            widget.deleteLater()
        self._widgets = []
        self._empty.setVisible(not has_source)
        if not has_source:
            return
        for index, row in enumerate(rows):
            dot = _Dot(self)
            dot.set_state(row.state)
            name = QLabel(row.label, self)
            detail = QLabel(row.detail, self)
            detail.setToolTip(row.tooltip)
            muted = row.state != "found"
            name.setStyleSheet(f"color: {COLORS['ink_muted'] if muted else COLORS['ink']};")
            detail.setStyleSheet(f"color: {COLORS['ink_muted']};")
            self._grid.addWidget(dot, index, 0, Qt.AlignmentFlag.AlignVCenter)
            self._grid.addWidget(name, index, 1)
            self._grid.addWidget(detail, index, 2)
            self._widgets += [dot, name, detail]


class _Page(QWidget):
    changed = Signal()

    def __init__(self, intro: str, parent=None):
        super().__init__(parent)
        self.body = QVBoxLayout(self)
        self.body.setContentsMargins(22, 22, 22, 22)
        self.body.setSpacing(SECTION_GAP)
        self.body.addWidget(help_label(intro, self))

    def finish(self) -> None:
        self.body.addStretch(1)


class TargetPage(_Page):
    def __init__(self, parent=None):
        super().__init__(
            "Optional extra details about the site under investigation. They focus the "
            "memory results on that site.",
            parent,
        )
        self.host = QLineEdit(self)
        self.host.setPlaceholderText("e.g. 1.2.3.4:8080")
        self.username = QLineEdit(self)
        self.username.setPlaceholderText("e.g. admin")
        self.report_timezone = QLineEdit(self)
        self.report_timezone.setPlaceholderText("e.g. Asia/Colombo — blank uses this computer's")
        self.body.addLayout(
            labelled(
                field_label("Host and port", self),
                self.host,
                "Use when the site is reached by IP address instead of an onion address.",
                self,
            )
        )
        self.body.addLayout(
            labelled(
                field_label("Username", self),
                self.username,
                "A known account name to highlight in recovered searches.",
                self,
            )
        )
        self.body.addLayout(
            labelled(
                field_label("Report timezone", self),
                self.report_timezone,
                "An IANA zone name the report's plain-English section shows local times "
                "in, alongside UTC.",
                self,
            )
        )
        self.finish()


class InputsPage(_Page):
    """Each auto-discovered input, with Change… and (when changed) Reset."""

    def __init__(self, parent=None):
        super().__init__(
            "These were found in the evidence folder. Change one to analyse a different "
            "file — for example a Tor data folder from a mounted disk.",
            parent,
        )
        self._evidence_dir: str | None = None
        self._discovered: dict = {}
        self._overrides: dict[str, str] = {}
        self._rows: dict[str, tuple] = {}

        grid = QGridLayout()
        grid.setHorizontalSpacing(10)
        grid.setVerticalSpacing(12)
        grid.setColumnStretch(2, 1)
        for index, spec in enumerate(INPUT_SPECS):
            dot = _Dot(self)
            name = QLabel(spec.label, self)
            path = PathLabel("not found", self)
            change = QPushButton("Change…", self)
            change.clicked.connect(lambda _=False, s=spec: self._change(s))
            reset = QPushButton("Reset", self)
            reset.setToolTip("Go back to what was found in the evidence folder")
            reset.clicked.connect(lambda _=False, key=spec.key: self._reset(key))
            grid.addWidget(dot, index, 0, Qt.AlignmentFlag.AlignVCenter)
            grid.addWidget(name, index, 1)
            grid.addWidget(path, index, 2)
            grid.addWidget(change, index, 3)
            grid.addWidget(reset, index, 4)
            self._rows[spec.key] = (dot, path, reset)
        self.body.addLayout(grid)
        self.finish()
        self._refresh()

    def set_discovered(self, discovered: dict, evidence_dir: str | None) -> None:
        self._discovered = dict(discovered)
        self._evidence_dir = evidence_dir
        self._refresh()

    def overrides(self) -> dict[str, str]:
        return dict(self._overrides)

    def clear_overrides(self) -> None:
        self._overrides.clear()
        self._refresh()

    def _change(self, spec) -> None:
        current = self._overrides.get(spec.key) or self._discovered.get(spec.key)
        start = current or self._evidence_dir or str(Path.home())
        if spec.is_dir:
            chosen = QFileDialog.getExistingDirectory(self, f"Select {spec.label}", start)
        else:
            chosen, _ = QFileDialog.getOpenFileName(self, f"Select {spec.label}", start)
        if chosen:
            self._overrides[spec.key] = chosen
            self._refresh()
            self.changed.emit()

    def _reset(self, key: str) -> None:
        self._overrides.pop(key, None)
        self._refresh()
        self.changed.emit()

    def _refresh(self) -> None:
        for spec in INPUT_SPECS:
            dot, path, reset = self._rows[spec.key]
            override = self._overrides.get(spec.key)
            value = override or self._discovered.get(spec.key) or ""
            shown = display_path(value, self._evidence_dir) if value else ""
            path.set_path(value, shown + ("  · chosen manually" if override else ""))
            dot.set_state("found" if value else "missing")
            reset.setVisible(bool(override))


class DiskPage(_Page):
    """None / a disk image file / an already-mounted volume."""

    NONE, IMAGE, MOUNTED = range(3)

    def __init__(self, mount_supported: bool, mount_reason: str, parent=None):
        super().__init__(
            "A disk image adds deeper evidence: every downloaded file on the volume, deleted "
            "files and the file-system change log, and memory Windows wrote to disk.",
            parent,
        )
        self._mount_supported = mount_supported
        self._choice = QButtonGroup(self)
        choices = QVBoxLayout()
        choices.setSpacing(10)
        for value, text in (
            (self.NONE, "Don't use a disk image"),
            (self.IMAGE, "Analyse a disk image file"),
            (self.MOUNTED, "Use a volume I already mounted"),
        ):
            button = QRadioButton(text, self)
            self._choice.addButton(button, value)
            choices.addWidget(button)
        self._choice.button(self.NONE).setChecked(True)
        self._choice.idToggled.connect(self._on_choice)
        self.body.addLayout(choices)

        self._stack = QStackedWidget(self)
        self._stack.addWidget(QWidget(self))  # NONE: nothing to show

        image_page = QWidget(self)
        image_layout = QVBoxLayout(image_page)
        image_layout.setContentsMargins(0, 0, 0, 0)
        image_layout.setSpacing(ROW_GAP)
        self.image = PathPicker(
            "No image selected", is_dir=False, file_filter=IMAGE_FILTER, parent=self
        )
        self.image.changed.connect(self.changed)
        image_layout.addLayout(
            labelled(
                field_label("Disk image file", self),
                self.image,
                "Supported: .vdi, .vmdk, .vhd, .vhdx, .qcow2 and raw images. A VirtualBox "
                "snapshot has to be flattened into one file first.",
                self,
            )
        )
        self.mount_box = QCheckBox("Open the image and analyse its files", self)
        self.mount_box.setChecked(mount_supported)
        self.mount_box.setEnabled(mount_supported)
        self.mount_box.toggled.connect(self.changed)
        image_layout.addLayout(
            option(
                self.mount_box,
                (
                    "Opened read-only — nothing on the image can change. Your computer asks "
                    "for your password once."
                    if mount_supported
                    else mount_reason
                ),
                self,
            )
        )
        self.carve_box = QCheckBox("Also search every byte for onion addresses", self)
        self.carve_box.toggled.connect(self.changed)
        image_layout.addLayout(
            option(
                self.carve_box,
                "Finds addresses in deleted or unused space. Slow on large images.",
                self,
            )
        )
        self._stack.addWidget(image_page)

        mounted_page = QWidget(self)
        mounted_layout = QVBoxLayout(mounted_page)
        mounted_layout.setContentsMargins(0, 0, 0, 0)
        self.mounted_root = PathPicker("No folder selected", is_dir=True, parent=self)
        self.mounted_root.changed.connect(self.changed)
        mounted_layout.addLayout(
            labelled(
                field_label("Mounted volume folder", self),
                self.mounted_root,
                "Mount it read-only with ntfs-3g and the options "
                "ro,show_sys_files,streams_interface=windows so system files are visible.",
                self,
            )
        )
        self._stack.addWidget(mounted_page)
        self.body.addWidget(self._stack)
        self.finish()

    def _on_choice(self, choice: int, checked: bool) -> None:
        if checked:
            self._stack.setCurrentIndex(choice)
            self.changed.emit()

    def values(self) -> dict:
        choice = self._choice.checkedId()
        image = self.image.path() if choice == self.IMAGE else ""
        return {
            "disk_image": image or None,
            "mount_image": bool(image) and self.mount_box.isChecked() and self._mount_supported,
            "carve_image": bool(image) and self.carve_box.isChecked(),
            "disk_root": (self.mounted_root.path() or None) if choice == self.MOUNTED else None,
        }


class MemoryPage(_Page):
    def __init__(self, parent=None):
        super().__init__(
            "Optional settings for the memory image. The defaults work for most cases.",
            parent,
        )
        self.source_type = QComboBox(self)
        for label, value in SOURCE_TYPE_CHOICES:
            self.source_type.addItem(label, value)
        self.source_type.currentIndexChanged.connect(self.changed)
        self.body.addLayout(
            labelled(field_label("Memory image type", self), self.source_type, None, self)
        )

        self.vol3 = PathPicker(
            "Not set — the structural pass is skipped", is_dir=False, parent=self
        )
        self.vol3.set_path(shutil.which("vol") or "")
        self.body.addLayout(
            labelled(
                field_label("Volatility3", self),
                self.vol3,
                "Adds a second pass listing processes, network connections, open files and "
                "command lines. Filled in automatically when Volatility3 is installed.",
                self,
            )
        )

        self.extract_process = QLineEdit(self)
        self.extract_process.setPlaceholderText("e.g. firefox.exe")
        self.extract_pid = QLineEdit(self)
        self.extract_pid.setPlaceholderText("optional")
        self.extract_pid.setValidator(QIntValidator(1, 2**31 - 1, self))
        self.extract_pid.setMaximumWidth(140)
        pair = QHBoxLayout()
        pair.setSpacing(ROW_GAP)
        pair.addLayout(labelled(field_label("Only this process", self), self.extract_process), 1)
        pair.addLayout(labelled(field_label("Process ID", self), self.extract_pid))
        self.body.addLayout(pair)
        self.body.addWidget(
            help_label(
                "For a full memory image: analyse just this program's memory instead of "
                "everything. Needs Volatility3.",
                self,
            )
        )
        self.finish()

    def values(self) -> dict:
        pid = self.extract_pid.text().strip()
        return {
            "source_type": self.source_type.currentData(),
            "vol3_path": self.vol3.path() or None,
            "vol3_extract_process": self.extract_process.text().strip() or None,
            "vol3_extract_pid": int(pid) if pid else None,
        }


class OptionsPanel(QWidget):
    """'More options' toggle + a tabbed card with the four pages."""

    changed = Signal()

    def __init__(self, mount_supported: bool, mount_reason: str, parent=None):
        super().__init__(parent)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(FIELD_GAP)
        self._toggle = QPushButton("+ More options", self)
        self._toggle.setProperty("class", "link")
        self._toggle.clicked.connect(lambda: self.set_expanded(not self._card.isVisible()))
        layout.addWidget(self._toggle, alignment=Qt.AlignmentFlag.AlignLeft)

        self.target = TargetPage(self)
        self.inputs = InputsPage(self)
        self.disk = DiskPage(mount_supported, mount_reason, self)
        self.memory = MemoryPage(self)
        for page in (self.inputs, self.disk, self.memory):
            page.changed.connect(self.changed)

        # The tab pane is the card itself (styled in theme.qss) -- no frame inside a frame.
        self._card = QTabWidget(self)
        self._card.setObjectName("optionsTabs")
        self._card.addTab(self.target, "Target")
        self._card.addTab(self.inputs, "Inputs")
        self._card.addTab(self.disk, "Disk image")
        self._card.addTab(self.memory, "Memory")
        self._card.setVisible(False)
        layout.addSpacing(4)
        layout.addWidget(self._card)

    def set_expanded(self, expanded: bool) -> None:
        self._card.setVisible(expanded)
        self._toggle.setText("− Fewer options" if expanded else "+ More options")
