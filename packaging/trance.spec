# PyInstaller spec for the TRANCE desktop app (Windows and Linux). Build it through
# scripts/build.py, which CI's release workflow also uses:
#
#     python scripts/build.py app        ->  dist/TRANCE/  (+ an archive in dist/release/)
#
# One folder, not --onefile: a ~250 MB single file would unpack itself to a temp folder on
# every launch and again for every analysis child process (gui_main.py --run-analysis).
# If packaging/acquire/trance-acquire.exe (+ .sha256) exists -- scripts/build.py acquire on
# Windows, or CI copying it in -- it is shipped inside the app for the Build tab to save.
# A second program, vol[.exe] (Volatility3's CLI), sits next to TRANCE[.exe] and shares its
# _internal folder: the memory module's structural pass runs it as it runs `vol` from a venv.

import re
import sys
from pathlib import Path

from PyInstaller.utils.hooks import collect_data_files, collect_submodules, copy_metadata

ROOT = Path(SPECPATH).parent  # noqa: F821 (SPECPATH is defined by PyInstaller)
ACQUIRE = Path(SPECPATH) / "acquire"  # noqa: F821
sys.path.insert(0, str(ROOT))
from core.provenance import LIBRARIES  # noqa: E402

EXCLUDED = ["tkinter", "pytest", "mypy", "black", "ruff"]

datas = [
    (str(ROOT / "report_template.html.j2"), "."),
    (str(ROOT / "gui" / "theme.qss"), "gui"),
    (
        str(ROOT / "modules" / "module_c_memory" / "report_template.html.j2"),
        "modules/module_c_memory",
    ),
    # Windows has no OS time zone database; zoneinfo reads tzdata's data files.
    *collect_data_files("tzdata"),
]
# Every report records these libraries' versions (core/provenance.py) from their metadata,
# which PyInstaller does not copy by itself.
for name in LIBRARIES:
    datas += copy_metadata(name)
if (ACQUIRE / "trance-acquire.exe").is_file():
    datas += [
        (str(ACQUIRE / "trance-acquire.exe"), "acquire"),
        (str(ACQUIRE / "trance-acquire.exe.sha256"), "acquire"),
    ]

# main.py loads the modules with importlib.import_module, which PyInstaller can't follow;
# regipy imports ShellBags' native helpers (regipy[full]) inside a try block.
hiddenimports = [*collect_submodules("modules"), *collect_submodules("regipy.plugins")]
hiddenimports += ["pyfwsi", "pyfwps"]

a = Analysis(  # noqa: F821
    [str(ROOT / "gui_main.py")],
    pathex=[str(ROOT)],
    binaries=[],
    datas=datas,
    hiddenimports=hiddenimports,
    excludes=EXCLUDED,
    noarchive=False,
)

# PySide6's hook ships nearly all of Qt (3D, Charts, Multimedia, QML modules, ...): ~610 MB.
# TRANCE uses Widgets + WebEngine only, so keep the Qt libraries in their dependency closure
# (checked with ldd on Linux) plus the platform integrations, and drop Qt's QML modules and
# UI translations (the app is English-only; Chromium's own locales stay).
QT_KEEP = {
    "Core", "Gui", "Widgets", "Network", "DBus", "OpenGL", "PrintSupport", "Svg",
    "WebEngineCore", "WebEngineWidgets", "WebChannel", "Positioning",
    "Quick", "QuickWidgets", "Qml", "QmlMeta", "QmlModels", "QmlWorkerScript",
    "XcbQpa", "WaylandClient", "WlShellIntegration", "EglFSDeviceIntegration", "EglFsKmsSupport",
}  # fmt: skip
QT_LIB = re.compile(r"(?:^|[\\/])(?:lib)?Qt6(\w+?)(?:\.so\.6|\.dll)$")
# Plugins that need one of the libraries dropped above.
QT_PLUGIN_DROP = ("qpdf", "virtualkeyboard", "position_nmea", "quick3dprofiler")


def _wanted(entry) -> bool:
    dest = entry[0].replace("\\", "/")
    # Linux wheels put these under PySide6/Qt/, Windows wheels directly under PySide6/.
    if re.search(r"PySide6/(?:Qt/)?qml/", dest):
        return False
    if re.search(r"PySide6/(?:Qt/)?translations/[^/]+\.qm$", dest):
        return False
    if re.search(r"PySide6/(?:Qt/)?plugins/", dest) and any(n in dest for n in QT_PLUGIN_DROP):
        return False
    match = QT_LIB.search(dest)
    return match is None or match.group(1) in QT_KEEP


a.binaries = [entry for entry in a.binaries if _wanted(entry)]
a.datas = [entry for entry in a.datas if _wanted(entry)]

# Volatility3 finds its plugins and symbol tables by walking its own folders on disk
# (volatility3.framework.import_files uses os.walk), so it is kept as .py files, not in
# the PYZ archive. Symbols for a new Windows build are downloaded and cached on first use
# (~/.cache/volatility3), exactly as from source.
VOL_MODE = {"volatility3": "py"}
vol = Analysis(  # noqa: F821
    [str(Path(SPECPATH) / "vol_entry.py")],  # noqa: F821
    pathex=[str(ROOT)],
    datas=collect_data_files("volatility3"),
    hiddenimports=collect_submodules("volatility3"),
    excludes=EXCLUDED,
    module_collection_mode=VOL_MODE,
)

pyz = PYZ(a.pure)  # noqa: F821
exe = EXE(  # noqa: F821
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name="TRANCE",
    console=False,  # also the --run-analysis child; QProcess gives it real stdout pipes
    upx=False,
)
vol_exe = EXE(  # noqa: F821
    PYZ(vol.pure),  # noqa: F821
    vol.scripts,
    [],
    exclude_binaries=True,
    name="vol",
    # Run only by the (windowless) analysis child with piped output; a console program
    # would open a console window for every plugin on Windows.
    console=False,
    upx=False,
)
coll = COLLECT(  # noqa: F821
    exe,
    a.binaries,
    a.datas,
    vol_exe,
    vol.binaries,
    vol.datas,
    strip=False,
    upx=False,
    name="TRANCE",
)
