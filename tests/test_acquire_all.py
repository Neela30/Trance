import json
import sys

import pytest

import acquire_all
from core.exceptions import AcquisitionError


def test_acquire_refuses_on_non_windows(tmp_path, monkeypatch):
    monkeypatch.setattr(sys, "platform", "linux")
    with pytest.raises(AcquisitionError, match="only runs on Windows"):
        acquire_all.acquire(tmp_path)


def test_acquire_requires_elevation(tmp_path, monkeypatch):
    monkeypatch.setattr(sys, "platform", "win32")
    monkeypatch.setattr(acquire_all, "is_admin", lambda: False)
    with pytest.raises(AcquisitionError, match="elevated"):
        acquire_all.acquire(tmp_path)


def test_acquire_writes_manifest_with_one_section_per_category(tmp_path, monkeypatch):
    monkeypatch.setattr(sys, "platform", "win32")
    monkeypatch.setattr(acquire_all, "is_admin", lambda: True)
    monkeypatch.setattr(
        acquire_all,
        "_acquire_registry",
        lambda output_dir, ntuser_user: {"SYSTEM": {"status": "ok", "path": "registry/SYSTEM_x"}},
    )
    monkeypatch.setattr(
        acquire_all,
        "_acquire_memory",
        lambda output_dir, winpmem_path: {
            "live_dump": {"status": "ok", "path": "memory/firefox_1_x.bin"}
        },
    )
    monkeypatch.setattr(
        acquire_all,
        "_acquire_disk",
        lambda output_dir, tbd, ps, tds: {"profile": {"status": "skipped"}},
    )

    manifest = acquire_all.acquire(tmp_path)

    assert manifest["registry"]["SYSTEM"]["status"] == "ok"
    assert manifest["memory"]["live_dump"]["status"] == "ok"
    assert manifest["disk"]["profile"]["status"] == "skipped"

    written = json.loads((tmp_path / "acquire_manifest.json").read_text())
    assert written["registry"]["SYSTEM"]["path"] == "registry/SYSTEM_x"


def test_acquire_writes_paths_relative_to_the_evidence_folder(tmp_path, monkeypatch):
    # Real run: --output-dir evidence, relative to the acquire-time CWD, so submodules hand
    # back "evidence/registry/..." -- meaningless once the folder is copied elsewhere.
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(sys, "platform", "win32")
    monkeypatch.setattr(acquire_all, "is_admin", lambda: True)
    monkeypatch.setattr(
        acquire_all,
        "_acquire_registry",
        lambda output_dir, ntuser_user: {
            "SYSTEM": {"status": "ok", "path": str(output_dir / "registry" / "SYSTEM_x")},
            "custody_log_path": str(output_dir / "registry" / "custody.json"),
        },
    )
    monkeypatch.setattr(
        acquire_all,
        "_acquire_memory",
        lambda output_dir, winpmem_path: {
            "full_image": {
                "status": "ok",
                "path": str(output_dir / "memory" / "fullmem.raw"),
                "winpmem_path": "C:\\tools\\winpmem.exe",
            }
        },
    )
    monkeypatch.setattr(acquire_all, "_acquire_disk", lambda output_dir, tbd, ps, tds: {})

    acquire_all.acquire(acquire_all.Path("evidence"))

    written = json.loads((tmp_path / "evidence" / "acquire_manifest.json").read_text())
    assert written["registry"]["SYSTEM"]["path"] == "registry/SYSTEM_x"
    assert written["registry"]["custody_log_path"] == "registry/custody.json"
    assert written["memory"]["full_image"]["path"] == "memory/fullmem.raw"
    # a source location on the target is provenance, not an evidence output -- untouched
    assert written["memory"]["full_image"]["winpmem_path"] == "C:\\tools\\winpmem.exe"


def test_acquire_isolates_one_category_failure_from_the_others(tmp_path, monkeypatch):
    monkeypatch.setattr(sys, "platform", "win32")
    monkeypatch.setattr(acquire_all, "is_admin", lambda: True)
    monkeypatch.setattr(
        acquire_all,
        "_acquire_registry",
        lambda output_dir, ntuser_user: {"status": "error", "message": "boom"},
    )
    monkeypatch.setattr(
        acquire_all,
        "_acquire_memory",
        lambda output_dir, winpmem_path: {"live_dump": {"status": "ok", "path": "memory/x.bin"}},
    )
    monkeypatch.setattr(
        acquire_all, "_acquire_disk", lambda output_dir, tbd, ps, tds: {"profile": {}}
    )

    manifest = acquire_all.acquire(tmp_path)

    assert manifest["registry"]["status"] == "error"
    assert manifest["memory"]["live_dump"]["status"] == "ok"


def test_acquire_disk_reports_error_when_auto_discovery_finds_nothing(tmp_path, monkeypatch):
    # No path given at all now means "auto-discover" (see modules/module_b_disk/acquire.py),
    # not "skip" -- only a scan that genuinely finds nothing is reported as an error, and
    # the scan itself must never touch the real filesystem in a test.
    monkeypatch.setattr(acquire_all.disk_acquire, "find_tor_browser_installations", list)

    result = acquire_all._acquire_disk(tmp_path, None, None, None)

    for step in ("profile", "tor_dir"):
        assert result[step]["status"] == "error"
        assert "No Tor Browser installation found" in result[step]["message"]
    # The downloads scan is still attempted (skipped here only because it's not Windows).
    assert result["downloads"]["status"] == "skipped"


def test_acquire_memory_skips_full_image_when_no_winpmem_found(tmp_path, monkeypatch):
    monkeypatch.setattr(
        acquire_all.memory_dumper,
        "acquire",
        lambda output_dir: (_ for _ in ()).throw(AcquisitionError("no firefox.exe running")),
    )
    # find_winpmem_binaries() must never touch the real filesystem in a test -- same
    # class of bug already hit once with Tor Browser auto-discovery.
    monkeypatch.setattr(acquire_all.winpmem_acquire, "find_winpmem_binaries", list)

    result = acquire_all._acquire_memory(tmp_path, None)

    assert result["live_dump"]["status"] == "error"
    assert result["full_image"]["status"] == "skipped"


def test_acquire_memory_auto_discovers_winpmem_and_still_tries_full_image_after_live_dump_fails(
    tmp_path, monkeypatch
):
    monkeypatch.setattr(
        acquire_all.memory_dumper,
        "acquire",
        lambda output_dir: (_ for _ in ()).throw(AcquisitionError("no firefox.exe running")),
    )
    found = tmp_path / "winpmem.exe"
    monkeypatch.setattr(acquire_all.winpmem_acquire, "find_winpmem_binaries", lambda: [found])
    monkeypatch.setattr(
        acquire_all.winpmem_acquire, "acquire", lambda path, output_dir: tmp_path / "fullmem.raw"
    )

    result = acquire_all._acquire_memory(tmp_path, None)

    assert result["live_dump"]["status"] == "error"
    assert result["full_image"]["status"] == "ok"
    assert result["full_image"]["winpmem_path"] == str(found)


def test_cli_fails_cleanly_off_windows(monkeypatch, tmp_path):
    monkeypatch.setattr(sys, "platform", "linux")
    exit_code = acquire_all.main(["--output-dir", str(tmp_path)])
    assert exit_code == 1
