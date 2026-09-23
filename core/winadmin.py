"""Shared elevation check for Windows-only acquisition tools."""

from __future__ import annotations

import sys

if sys.platform == "win32":
    import ctypes

    def is_admin() -> bool:
        try:
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            return False

else:

    def is_admin() -> bool:
        return False
