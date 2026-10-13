"""Pure logic for the "Generate acquisition EXE" feature: preflight checks and the
PyInstaller command line. No Qt import, so it's testable without a PySide6 install --
same separation gui/pipeline_inputs.py already uses for module_kwargs_from_resolved()."""

from __future__ import annotations

import importlib.util
import os
import sys
from pathlib import Path

ACQUIRE_SCRIPT = Path(__file__).resolve().parent.parent / "acquire_all.py"
DEFAULT_EXE_NAME = "trance-acquire"
DEFAULT_BUILDS_DIR = Path.home() / "trance-builds"

NOT_WINDOWS_REASON = (
    "PyInstaller cannot cross-compile: trance-acquire.exe has to be built on Windows. "
    "Build it on a clean Windows machine (never the suspect one), then carry the exe and "
    "its .sha256 to the tools drive."
)
ELEVATED_WARNING = (
    "This app is running with administrator rights. PyInstaller warns about elevated "
    "builds and newer versions refuse them. Restarting this app from a normal "
    "(non-administrator) session is recommended. The built exe still asks for "
    "administrator rights on the target by itself."
)


def default_output_name() -> str:
    return f"{DEFAULT_EXE_NAME}.exe"


def build_support(platform: str | None = None) -> tuple[bool, str]:
    """Whether this machine can build trance-acquire.exe, and why not if it can't."""
    if (platform or sys.platform) != "win32":
        return False, NOT_WINDOWS_REASON
    if getattr(sys, "frozen", False):
        return False, (
            "The packaged app can't run PyInstaller. Build from a source checkout: "
            "python gui_main.py, with requirements-dev.txt installed."
        )
    return True, ""


def is_elevated() -> bool:
    if sys.platform == "win32":
        from core.winadmin import is_admin

        return is_admin()
    geteuid = getattr(os, "geteuid", None)
    return bool(geteuid) and geteuid() == 0


def elevation_warning() -> str | None:
    return ELEVATED_WARNING if is_elevated() else None


def check_prerequisites(script: Path = ACQUIRE_SCRIPT) -> list[str]:
    """Returns human-readable blocking problems; an empty list means it's safe to build.
    Checked here instead of after a build starts so a missing tool or a 32-bit
    interpreter produces a clear message instead of a broken/half-built exe."""
    problems = []

    if not script.exists():
        problems.append(f"Acquisition script not found: {script}")

    if sys.maxsize <= 2**32:
        problems.append(
            "This Python interpreter is 32-bit -- it would produce a 32-bit exe, not "
            "the required 64-bit one. Install 64-bit Python and retry."
        )

    if importlib.util.find_spec("PyInstaller") is None:
        problems.append(
            "PyInstaller is not installed. Install it with: pip install -r requirements-dev.txt"
        )

    return problems


def build_pyinstaller_argv(
    script: Path,
    dist_dir: Path,
    work_dir: Path,
    spec_dir: Path,
    exe_name: str = DEFAULT_EXE_NAME,
) -> list[str]:
    """python -m PyInstaller, not a bare "pyinstaller" on PATH -- it isn't always on
    PATH (see CLAUDE.md's Windows-VM note). --uac-admin embeds a manifest so the built
    exe requests elevation itself instead of relying on the user to right-click Run as
    Administrator. --distpath/--workpath/--specpath keep every build artifact inside
    the caller's temp directory, never the repo."""
    return [
        sys.executable,
        "-m",
        "PyInstaller",
        "--onefile",
        "--noconfirm",
        "--clean",
        "--name",
        exe_name,
        "--uac-admin",
        "--distpath",
        str(dist_dir),
        "--workpath",
        str(work_dir),
        "--specpath",
        str(spec_dir),
        str(script),
    ]


def built_exe_path(dist_dir: Path, exe_name: str = DEFAULT_EXE_NAME) -> Path:
    return dist_dir / f"{exe_name}.exe"
