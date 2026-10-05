"""Opt-in integration test against a real UsrClass.dat hive, present only on this
development machine -- skipped everywhere else (CI, teammates' machines). The hive
itself is never committed (it lives entirely outside the repo, under
C:\\Users\\Admin\\Downloads\\, left there by a real acquisition run); only this test
file is. See _shellbags_patch.py's module docstring for the bug this proves fixed.
"""

from __future__ import annotations

from pathlib import Path

import pytest

_REAL_EVIDENCE_DIR = Path(r"C:\Users\Admin\Downloads\evidence\registry")
_REAL_HIVES = (
    sorted(_REAL_EVIDENCE_DIR.glob("UsrClass_*.dat")) if _REAL_EVIDENCE_DIR.is_dir() else []
)


@pytest.mark.skipif(not _REAL_HIVES, reason="real UsrClass.dat hive not present on this machine")
def test_shellbags_extraction_succeeds_against_the_real_hive():
    from modules.module_a_registry.extractors import extract_shellbags

    # Most recently acquired, if more than one real run has accumulated in the folder.
    hive_path = max(_REAL_HIVES, key=lambda p: p.stat().st_mtime)

    entries = extract_shellbags(hive_path)

    assert len(entries) > 0
    # Confirms the fix recovers genuinely Tor-relevant evidence, not just that nothing
    # crashed -- the same real finding this patch was built and verified against.
    assert any("tor browser" in (e.get("path") or "").lower() for e in entries)
