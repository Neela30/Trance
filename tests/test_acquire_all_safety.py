"""acquire_all.py's examiner-safety additions: the tool's own SHA-256 in the manifest, the
manifest's sidecar, the refusal to write into a non-empty folder, and the volume warnings
(which must only ever warn)."""

import hashlib
import json
import sys
from pathlib import Path

import pytest

import acquire_all
from core.evidence_integrity import verify_evidence
from core.exceptions import AcquisitionError


@pytest.fixture
def stubbed(monkeypatch):
    """Every category stubbed, as in test_acquire_all.py; no real acquisition."""
    monkeypatch.setattr(sys, "platform", "win32")
    monkeypatch.setattr(acquire_all, "is_admin", lambda: True)
    monkeypatch.setattr(acquire_all, "_acquire_registry", lambda output_dir, ntuser_user: {})
    monkeypatch.setattr(acquire_all, "_acquire_memory", lambda output_dir, winpmem_path: {})
    monkeypatch.setattr(acquire_all, "_acquire_disk", lambda output_dir, tbd, ps, tds: {})
    monkeypatch.setattr(acquire_all.acquire_ntfs, "system_drive", lambda: "Q:")


def test_manifest_records_the_tools_own_sha256(tmp_path, stubbed):
    manifest = acquire_all.acquire(tmp_path / "evidence", include_ntfs=False)

    tool = manifest["tool"]
    assert tool["frozen"] is False  # from a checkout: the script itself is hashed
    assert Path(tool["path"]) == Path(acquire_all.__file__).resolve()
    assert tool["sha256"] == hashlib.sha256(Path(acquire_all.__file__).read_bytes()).hexdigest()
    written = json.loads((tmp_path / "evidence" / "acquire_manifest.json").read_text())
    assert written["tool"]["sha256"] == tool["sha256"]


def test_frozen_exe_hashes_itself(tmp_path, monkeypatch):
    exe = tmp_path / "trance-acquire.exe"
    exe.write_bytes(b"MZ fake exe")
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    monkeypatch.setattr(sys, "executable", str(exe))

    tool = acquire_all.tool_identity()

    assert tool == {
        "path": str(exe.resolve()),
        "sha256": hashlib.sha256(b"MZ fake exe").hexdigest(),
        "frozen": True,
    }


def test_manifest_gets_a_sidecar_the_examiner_side_verifies(tmp_path, stubbed):
    out = tmp_path / "evidence"
    acquire_all.acquire(out, include_ntfs=False)

    assert b"\r" not in (out / "acquire_manifest.json.sha256").read_bytes()
    assert verify_evidence(out)["status"] == "verified"
    manifest = out / "acquire_manifest.json"
    manifest.write_text(manifest.read_text().replace("acquired_at", "acquired_AT"))
    assert verify_evidence(out)["status"] == "failed"


def test_refuses_a_non_empty_output_folder_and_touches_nothing(tmp_path, stubbed):
    out = tmp_path / "evidence"
    out.mkdir()
    earlier = out / "acquire_manifest.json"
    earlier.write_text("earlier acquisition")

    with pytest.raises(AcquisitionError, match="not empty"):
        acquire_all.acquire(out, include_ntfs=False)
    assert earlier.read_text() == "earlier acquisition"
    assert [p.name for p in out.iterdir()] == ["acquire_manifest.json"]


def test_an_existing_empty_output_folder_is_fine(tmp_path, stubbed):
    out = tmp_path / "evidence"
    out.mkdir()
    acquire_all.acquire(out, include_ntfs=False)
    assert (out / "acquire_manifest.json").is_file()


def test_volume_warnings_cover_system_volume_and_tools_drive():
    warnings = acquire_all.volume_warnings(
        Path("C:/evidence"), Path("C:/tools/trance-acquire.exe"), "C:"
    )
    assert len(warnings) == 2
    assert "system volume" in warnings[0]
    assert "same volume as the acquisition tool" in warnings[1]

    assert acquire_all.volume_warnings(Path("E:/ev"), Path("D:/trance-acquire.exe"), "C:") == []
    only_tools = acquire_all.volume_warnings(Path("D:/ev"), Path("D:/trance-acquire.exe"), "C:")
    assert len(only_tools) == 1 and "acquisition tool" in only_tools[0]


def test_volume_warnings_are_case_insensitive():
    assert acquire_all.volume_warnings(Path("c:/ev"), Path("D:/x.exe"), "C:")


def test_volume_warnings_only_warn_and_end_up_in_the_manifest(
    tmp_path, stubbed, monkeypatch, capsys
):
    monkeypatch.setattr(acquire_all, "volume_warnings", lambda *a: ["on the system volume"])

    manifest = acquire_all.acquire(tmp_path / "evidence", include_ntfs=False)

    assert manifest["warnings"] == ["on the system volume"]
    assert "on the system volume" in capsys.readouterr().err
    assert (tmp_path / "evidence" / "acquire_manifest.json").is_file()  # still acquired


def test_bundled_winpmem_next_to_the_tool_is_preferred(tmp_path, monkeypatch):
    tools = tmp_path / "tools"
    tools.mkdir()
    exe = tools / "trance-acquire.exe"
    exe.write_bytes(b"MZ")
    bundled = tools / "winpmem_mini_x64_rc2.exe"
    bundled.write_bytes(b"pmem")
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    monkeypatch.setattr(sys, "executable", str(exe))
    monkeypatch.setattr(
        acquire_all.winpmem_acquire,
        "find_winpmem_binaries",
        lambda: pytest.fail("the drive scan should not run when one is bundled"),
    )
    monkeypatch.setattr(
        acquire_all.memory_dumper,
        "acquire",
        lambda out: (_ for _ in ()).throw(AcquisitionError("no firefox.exe")),
    )
    used = []
    monkeypatch.setattr(
        acquire_all.winpmem_acquire,
        "acquire",
        lambda path, output_dir: used.append(path) or tmp_path / "fullmem.raw",
    )

    result = acquire_all._acquire_memory(tmp_path / "out", None)

    assert used == [bundled]
    assert result["full_image"]["winpmem_path"] == str(bundled)
