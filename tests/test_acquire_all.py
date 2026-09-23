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


def test_acquire_disk_skipped_without_any_disk_source(tmp_path):
    result = acquire_all._acquire_disk(tmp_path, None, None, None)
    assert result["profile"]["status"] == "skipped"
    assert result["tor_dir"]["status"] == "skipped"


def test_acquire_memory_skips_full_image_without_winpmem_path(tmp_path, monkeypatch):
    monkeypatch.setattr(
        acquire_all.memory_dumper,
        "acquire",
        lambda output_dir: (_ for _ in ()).throw(AcquisitionError("no firefox.exe running")),
    )
    result = acquire_all._acquire_memory(tmp_path, None)
    assert result["live_dump"]["status"] == "error"
    assert result["full_image"]["status"] == "skipped"


def test_cli_fails_cleanly_off_windows(monkeypatch, tmp_path):
    monkeypatch.setattr(sys, "platform", "linux")
    exit_code = acquire_all.main(["--output-dir", str(tmp_path)])
    assert exit_code == 1
