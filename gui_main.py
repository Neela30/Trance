"""TRANCE desktop GUI entrypoint (PySide6). Same backend as main.py/analyze_evidence.py
-- this is an additional way to drive the pipeline, not a replacement for the CLI exes.

    python gui_main.py [--output-dir output]
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from PySide6.QtWidgets import QApplication

from gui.main_window import MainWindow
from gui.theme import load_stylesheet

# The report tab is a static HTML page; Chromium's GPU path buys nothing there and
# segfaults QtWebEngine on some Linux/Wayland setups ("GBM is not supported ...
# Fallback to Vulkan rendering" followed by a crash as soon as a page loads). Must be
# set before QtWebEngine initializes; an explicit value from the environment wins.
os.environ.setdefault("QTWEBENGINE_CHROMIUM_FLAGS", "--disable-gpu")


def main(argv: list[str] | None = None) -> int:
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
