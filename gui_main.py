"""TRANCE desktop GUI entrypoint (PySide6). Same backend as main.py/analyze_evidence.py
-- this is an additional way to drive the pipeline, not a replacement for the CLI exes.

    python gui_main.py [--output-dir output]
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from PySide6.QtWidgets import QApplication

from gui.main_window import MainWindow


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="TRANCE desktop GUI.")
    parser.add_argument(
        "--output-dir", type=Path, default=Path("output"), help="Default: %(default)s"
    )
    args = parser.parse_args(argv)

    app = QApplication(sys.argv[:1])
    window = MainWindow(output_dir=args.output_dir)
    window.show()
    return app.exec()


if __name__ == "__main__":
    sys.exit(main())
