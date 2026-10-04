"""Shared bounded filesystem scanning for acquire-side auto-discovery (a Tor Browser
install, a WinPMEM binary, ...). Staged: fast/likely locations first (home directory,
Desktop, Downloads, Documents), falling back to a full per-drive walk only if those
come up empty -- the target artifact is almost always in the fast set, and a full
C:\\ walk is slow enough to want to avoid when it's not needed.
"""

from __future__ import annotations

import os
import string
import sys
from collections.abc import Iterator
from pathlib import Path

# Skip these by name, anywhere in the tree -- system-internal or reliably huge/
# irrelevant on a Windows target, not worth walking into during a scan.
SKIP_DIR_NAMES = {
    "$Recycle.Bin",
    "System Volume Information",
    "Windows",
    "WindowsApps",
    "Config.Msi",
    "$WinREAgent",
}
DEFAULT_MAX_DEPTH = 8


def fast_search_roots() -> list[Path]:
    home = Path.home()
    candidates = [home / "Desktop", home / "Downloads", home / "Documents", home]
    return [p for p in candidates if p.is_dir()]


def drive_search_roots() -> list[Path]:
    if sys.platform != "win32":
        return []
    roots = []
    for letter in string.ascii_uppercase:
        drive = Path(f"{letter}:/")
        if drive.is_dir():
            roots.append(drive)
    return roots


def walk_pruned(
    root: Path,
    max_depth: int = DEFAULT_MAX_DEPTH,
    skip_dir_names: frozenset[str] | set[str] | None = None,
) -> Iterator[tuple[Path, list[str], list[str]]]:
    """Same contract as os.walk (mutate dirnames in place to prune further descent),
    with skip_dir_names (default SKIP_DIR_NAMES) and max_depth already applied --
    callers only need to handle their own "found a match, stop descending here too"
    case."""
    skip = SKIP_DIR_NAMES if skip_dir_names is None else skip_dir_names
    root = root.resolve()
    base_depth = len(root.parts)
    for dirpath, dirnames, filenames in os.walk(root):
        current = Path(dirpath)
        if len(current.parts) - base_depth >= max_depth:
            dirnames[:] = []
            continue
        dirnames[:] = [d for d in dirnames if d not in skip]
        yield current, dirnames, filenames


def staged_scan(scan_root, search_roots: list[Path] | None = None) -> list[Path]:
    """Runs scan_root(root) -> list[Path] over each stage in turn (explicit
    search_roots if given, otherwise fast_search_roots() then drive_search_roots()),
    stopping at the first stage that finds anything."""
    if search_roots is not None:
        found = []
        for root in search_roots:
            found.extend(scan_root(root))
        return found

    found = []
    for root in fast_search_roots():
        found.extend(scan_root(root))
    if found:
        return found

    for root in drive_search_roots():
        found.extend(scan_root(root))
    return found
