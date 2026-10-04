"""The Analyse tab's optional sections -- everything main.py's CLI could do that the
form couldn't: per-input overrides of auto-discovery, a disk image to mount and/or
carve (or an already-mounted volume), and the Volatility3 memory options. Each section
is collapsed by default so the common case (pick a folder, run) stays one step."""

from __future__ import annotations

import shutil
from pathlib import Path

from PySide6.QtCore import Qt
from PySide6.QtGui import QIntValidator
from PySide6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QFileDialog,
    QFormLayout,
    QGridLayout,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from gui.analysis_request import INPUT_SPECS
from gui.theme import apply_eyebrow_style

MUTED = "color: #8b969c; font-size: 11.5px;"
IMAGE_FILTER = (
    "Disk images (*.vdi *.vmdk *.vhd *.vhdx *.qcow2 *.raw *.img *.dd *.001);;All files (*)"
)
SOURCE_TYPE_CHOICES = (
    ("Auto-detect", None),
    ("Live process dump (firefox.exe)", "process"),
    ("Full memory image (WinPMEM / VM)", "full-memory"),
)


def _help(text: str, parent: QWidget) -> QLabel:
    label = QLabel(text, parent)
    label.setWordWrap(True)
    label.setStyleSheet(MUTED)
    return label


class CollapsibleSection(QWidget):
    def __init__(self, title: str, parent=None):
        super().__init__(parent)
        self._title = title
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 10, 0, 0)
        self._toggle = QPushButton(f"+ {title}", self)
        self._toggle.setProperty("class", "link")
        self._toggle.clicked.connect(lambda: self.set_expanded(not self.body.isVisible()))
        layout.addWidget(self._toggle, alignment=Qt.AlignmentFlag.AlignLeft)
        self.body = QGroupBox(self)
        self.body.setVisible(False)
        layout.addWidget(self.body)

    def set_expanded(self, expanded: bool) -> None:
        self.body.setVisible(expanded)
        self._toggle.setText(f"{'−' if expanded else '+'} {self._title}")


class _PathField(QWidget):
    """Read-only path display with Browse… and a clear (×) button."""

    def __init__(self, placeholder: str, is_dir: bool, file_filter: str = "", parent=None):
        super().__init__(parent)
        self._is_dir = is_dir
        self._filter = file_filter
        self.field = QLineEdit(self)
        self.field.setReadOnly(True)
        self.field.setFocusPolicy(Qt.FocusPolicy.NoFocus)
        self.field.setPlaceholderText(placeholder)
        browse = QPushButton("Browse…", self)
        browse.clicked.connect(self._browse)
        clear = QPushButton("×", self)
        clear.setFixedWidth(32)
        clear.setToolTip("Clear")
        clear.clicked.connect(lambda: self.set_path(""))
        row = QHBoxLayout(self)
        row.setContentsMargins(0, 0, 0, 0)
        row.addWidget(self.field, 1)
        row.addWidget(browse)
        row.addWidget(clear)

    def path(self) -> str:
        return self.field.text().strip()

    def set_path(self, value: str) -> None:
        self.field.setText(value)
        self.field.setToolTip(value)

    def _browse(self) -> None:
        start = self.path() or str(Path.home())
        if self._is_dir:
            chosen = QFileDialog.getExistingDirectory(self, "Select folder", start)
        else:
            chosen, _ = QFileDialog.getOpenFileName(self, "Select file", start, self._filter)
        if chosen:
            self.set_path(chosen)


class InputsSection(CollapsibleSection):
    """What auto-discovery found in the evidence folder, each overridable -- the GUI
    form of main.py's --system/--ntuser/--amcache/--dump/--disk-profile/--tor-dir/
    --downloads-scan flags."""

    def __init__(self, parent=None):
        super().__init__("Review detected inputs", parent)
        self._discovered: dict = {}
        self._overrides: dict[str, str] = {}
        self._fields: dict[str, QLineEdit] = {}
        self._badges: dict[str, QLabel] = {}

        grid = QGridLayout()
        grid.setHorizontalSpacing(8)
        for row, spec in enumerate(INPUT_SPECS):
            label = QLabel(spec.label, self)
            apply_eyebrow_style(label)
            field = QLineEdit(self)
            field.setReadOnly(True)
            field.setFocusPolicy(Qt.FocusPolicy.NoFocus)
            badge = QLabel("", self)
            badge.setStyleSheet(MUTED)
            badge.setMinimumWidth(56)
            change = QPushButton("Change…", self)
            change.clicked.connect(lambda _=False, s=spec: self._change(s))
            reset = QPushButton("↺", self)
            reset.setFixedWidth(32)
            reset.setToolTip("Back to what was detected")
            reset.clicked.connect(lambda _=False, key=spec.key: self._reset(key))
            grid.addWidget(label, row, 0)
            grid.addWidget(field, row, 1)
            grid.addWidget(badge, row, 2)
            grid.addWidget(change, row, 3)
            grid.addWidget(reset, row, 4)
            self._fields[spec.key] = field
            self._badges[spec.key] = badge
        grid.setColumnStretch(1, 1)

        layout = QVBoxLayout()
        layout.addWidget(
            _help(
                "Found automatically in the evidence folder. Change any input to analyse a "
                "different file, e.g. a Tor folder on a mounted disk.",
                self,
            )
        )
        layout.addLayout(grid)
        self.body.setLayout(layout)
        self._refresh()

    def set_discovered(self, discovered: dict) -> None:
        self._discovered = dict(discovered)
        self._refresh()

    def overrides(self) -> dict[str, str]:
        return dict(self._overrides)

    def clear_overrides(self) -> None:
        self._overrides.clear()
        self._refresh()

    def _change(self, spec) -> None:
        start = self._overrides.get(spec.key) or self._discovered.get(spec.key) or str(Path.home())
        if spec.is_dir:
            chosen = QFileDialog.getExistingDirectory(self, f"Select {spec.label}", start)
        else:
            chosen, _ = QFileDialog.getOpenFileName(self, f"Select {spec.label}", start)
        if chosen:
            self._overrides[spec.key] = chosen
            self._refresh()

    def _reset(self, key: str) -> None:
        self._overrides.pop(key, None)
        self._refresh()

    def _refresh(self) -> None:
        for spec in INPUT_SPECS:
            override = self._overrides.get(spec.key)
            value = override or self._discovered.get(spec.key) or ""
            field = self._fields[spec.key]
            field.setText(value)
            field.setToolTip(value)
            field.setPlaceholderText("not found")
            self._badges[spec.key].setText("override" if override else ("auto" if value else ""))


class DiskSection(CollapsibleSection):
    """main.py's --disk-image and --disk-root, plus mounting the image from the app."""

    def __init__(self, mount_supported: bool, mount_reason: str, parent=None):
        super().__init__("Add a disk image or mounted volume", parent)
        self.image = _PathField(
            "No disk image", is_dir=False, file_filter=IMAGE_FILTER, parent=self
        )
        self.mount_box = QCheckBox(
            "Mount read-only and analyse the volume: downloads, pagefile/hiberfil, $MFT, "
            "$UsnJrnl (asks for your administrator password)",
            self,
        )
        self.mount_box.setChecked(mount_supported)
        self.mount_box.setEnabled(mount_supported)
        if not mount_supported:
            self.mount_box.setToolTip(mount_reason)
        self.carve_box = QCheckBox(
            "Raw byte carve for onion addresses (slow: reads every byte)", self
        )
        self.mounted_root = _PathField("No mounted volume", is_dir=True, parent=self)

        layout = QVBoxLayout()
        image_label = QLabel("Disk image", self)
        apply_eyebrow_style(image_label)
        layout.addWidget(image_label)
        layout.addWidget(self.image)
        layout.addWidget(
            _help(
                "A standalone image: .vdi, .vmdk, .vhd(x), .qcow2 or raw. A VirtualBox "
                "snapshot must be flattened first (VBoxManage clonemedium).",
                self,
            )
        )
        layout.addWidget(self.mount_box)
        if not mount_supported:
            layout.addWidget(_help(mount_reason, self))
        layout.addWidget(self.carve_box)
        layout.addSpacing(8)
        root_label = QLabel("…or a volume you already mounted", self)
        apply_eyebrow_style(root_label)
        layout.addWidget(root_label)
        layout.addWidget(self.mounted_root)
        layout.addWidget(
            _help(
                "Mounted read-only with ntfs-3g -o ro,show_sys_files,streams_interface=windows "
                "so $MFT and $UsnJrnl are visible.",
                self,
            )
        )
        self.body.setLayout(layout)

    def values(self) -> dict:
        image = self.image.path()
        return {
            "disk_image": image or None,
            "mount_image": bool(image)
            and self.mount_box.isChecked()
            and self.mount_box.isEnabled(),
            "carve_image": bool(image) and self.carve_box.isChecked(),
            "disk_root": self.mounted_root.path() or None,
        }


class MemorySection(CollapsibleSection):
    """main.py's --source-type and the Volatility3 flags."""

    def __init__(self, parent=None):
        super().__init__("Memory analysis options", parent)
        self.source_type = QComboBox(self)
        for label, value in SOURCE_TYPE_CHOICES:
            self.source_type.addItem(label, value)
        detected = shutil.which("vol") or ""
        self.vol3 = _PathField(
            "Volatility3 not found on PATH — optional", is_dir=False, parent=self
        )
        self.vol3.set_path(detected)
        self.extract_process = QLineEdit(self)
        self.extract_process.setPlaceholderText("e.g. firefox.exe — full-memory images only")
        self.extract_pid = QLineEdit(self)
        self.extract_pid.setPlaceholderText("optional: exact PID instead of looking it up")
        self.extract_pid.setValidator(QIntValidator(1, 2**31 - 1, self))

        form = QFormLayout()
        form.addRow("Memory source", self.source_type)
        form.addRow("Volatility3 'vol'", self.vol3)
        form.addRow("Extract process", self.extract_process)
        form.addRow("Process ID", self.extract_pid)
        for field in (self.source_type, self.vol3, self.extract_process, self.extract_pid):
            apply_eyebrow_style(form.labelForField(field))
        layout = QVBoxLayout()
        layout.addWidget(
            _help(
                "With Volatility3 set, a structural pass (processes, network, files, command "
                "lines, hives) runs alongside string carving. Extracting one process narrows a "
                "full-memory image to that process before carving.",
                self,
            )
        )
        layout.addLayout(form)
        self.body.setLayout(layout)

    def values(self) -> dict:
        pid = self.extract_pid.text().strip()
        return {
            "source_type": self.source_type.currentData(),
            "vol3_path": self.vol3.path() or None,
            "vol3_extract_process": self.extract_process.text().strip() or None,
            "vol3_extract_pid": int(pid) if pid else None,
        }
