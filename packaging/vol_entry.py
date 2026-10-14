"""Entry point of the packaged app's own `vol` (Volatility3's CLI), built next to TRANCE by
packaging/trance.spec so the memory module's structural pass works as it does from a source
venv, where `pip install volatility3` puts `vol` on PATH."""

import multiprocessing
import sys

from volatility3.cli import main

if __name__ == "__main__":
    multiprocessing.freeze_support()
    sys.exit(main())
