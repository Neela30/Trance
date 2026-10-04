"""TRANCE desktop GUI entrypoint (PySide6) -- the primary way to run an analysis. Same
backend as main.py/analyze_evidence.py, which stay as the engine and a scriptable fallback.

    python gui_main.py [--output-dir output]

The same entry point (and so the same frozen trance-gui binary) also serves the GUI's
two child processes, dispatched before Qt is imported:

    gui_main.py --run-analysis <request.json>        gui.analysis_runner (cancellable run)
    gui_main.py --mount-helper session <image>       gui.mount_helper (via pkexec, as root)
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

# The report tab is a static HTML page; Chromium's GPU path buys nothing there and
# segfaults QtWebEngine on some Linux/Wayland setups ("GBM is not supported ...
# Fallback to Vulkan rendering" followed by a crash as soon as a page loads). Must be
# set before QtWebEngine initializes; an explicit value from the environment wins.
os.environ.setdefault("QTWEBENGINE_CHROMIUM_FLAGS", "--disable-gpu")


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    if args[:1] == ["--run-analysis"] and len(args) == 2:
        from gui.analysis_runner import run

        return run(Path(args[1]))
    if args[:1] == ["--mount-helper"]:
        from gui.mount_helper import main as mount_helper_main

        return mount_helper_main(args[1:])
    return _run_gui(args)


def _run_gui(argv: list[str]) -> int:
    from PySide6.QtWidgets import QApplication

    from gui.main_window import MainWindow
    from gui.theme import load_stylesheet

    parser = argparse.ArgumentParser(description="TRANCE desktop GUI.")
    parser.add_argument(
        "--output-dir", type=Path, default=Path("output"), help="Default: %(default)s"
    )
    args = parser.parse_args(argv)

    app = QApplication(sys.argv[:1])
    app.setStyleSheet(load_stylesheet())
    window = MainWindow(output_dir=args.output_dir)
    window.show()
    return app.exec()


if __name__ == "__main__":
    sys.exit(main())
