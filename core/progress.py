"""Progress of long steps (hash check, memory scan, Volatility), as stderr lines.

Readable as-is in a terminal; the desktop app shows them under its progress bar and moves the
bar with them (gui.analysis_runner.parse_activity). Never part of any output file.
"""

from __future__ import annotations

import sys

PREFIX = "progress: "


def report(text: str) -> None:
    print(PREFIX + text, file=sys.stderr, flush=True)
