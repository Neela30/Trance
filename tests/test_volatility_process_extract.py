import subprocess
from pathlib import Path

import pytest

from core.exceptions import AnalysisError
from modules.module_c_memory import volatility_analyze as va


def make_image(tmp_path):
    image = tmp_path / "image.raw"
    image.write_bytes(b"synthetic full-memory image bytes")
    return image


def _mock_pslist(monkeypatch, rows):
    def fake_run_one(vol_bin, image_path, plugin):
        assert plugin == "windows.pslist.PsList"
        return {"status": "ok", "message": None, "rows": rows, "row_count": len(rows)}

    monkeypatch.setattr(va, "_run_one", fake_run_one)


def test_find_process_pid_no_candidates(monkeypatch, tmp_path):
    _mock_pslist(monkeypatch, [{"PID": 100, "PPID": 4, "ImageFileName": "explorer.exe"}])
    result = va.find_process_pid("vol", make_image(tmp_path), "firefox.exe")
    assert result["status"] == "not_found"
    assert "may have already exited" in result["message"]
    assert result["chosen_pid"] is None


def test_find_process_pid_single_candidate(monkeypatch, tmp_path):
    _mock_pslist(monkeypatch, [{"PID": 4321, "PPID": 500, "ImageFileName": "firefox.exe"}])
    result = va.find_process_pid("vol", make_image(tmp_path), "firefox.exe")
    assert result["status"] == "ok"
    assert result["chosen_pid"] == 4321
    assert "lowest PID" in result["chosen_reason"]


def test_find_process_pid_prefers_parent_of_children(monkeypatch, tmp_path):
    # Main process 100 spawns content-process children with PPID=100; a decoy lower-PID
    # firefox.exe (PID 50) exists but is unrelated (no children pointing at it).
    _mock_pslist(
        monkeypatch,
        [
            {"PID": 50, "PPID": 4, "ImageFileName": "firefox.exe"},
            {"PID": 100, "PPID": 4, "ImageFileName": "firefox.exe"},
            {"PID": 150, "PPID": 100, "ImageFileName": "firefox.exe"},
            {"PID": 160, "PPID": 100, "ImageFileName": "firefox.exe"},
        ],
    )
    result = va.find_process_pid("vol", make_image(tmp_path), "firefox.exe")
    assert result["status"] == "ok"
    assert result["chosen_pid"] == 100
    assert "parent" in result["chosen_reason"]


def test_find_process_pid_case_insensitive_name_match(monkeypatch, tmp_path):
    _mock_pslist(monkeypatch, [{"PID": 7, "PPID": 4, "ImageFileName": "Firefox.EXE"}])
    result = va.find_process_pid("vol", make_image(tmp_path), "firefox.exe")
    assert result["status"] == "ok"
    assert result["chosen_pid"] == 7


def test_find_process_pid_propagates_pslist_failure(monkeypatch, tmp_path):
    monkeypatch.setattr(
        va,
        "_run_one",
        lambda vol_bin, image_path, plugin: {
            "status": "error",
            "message": "no symbols",
            "rows": [],
            "row_count": 0,
        },
    )
    result = va.find_process_pid("vol", make_image(tmp_path), "firefox.exe")
    assert result["status"] == "error"
    assert "no symbols" in result["message"]


def test_extract_process_memory_requires_output_file(tmp_path, monkeypatch):
    def fake_run(cmd, capture_output, text, timeout):
        return subprocess.CompletedProcess(cmd, returncode=0, stdout="[]", stderr="")

    monkeypatch.setattr(va.subprocess, "run", fake_run)
    with pytest.raises(AnalysisError, match="no \\(or an empty\\)"):
        va.extract_process_memory("vol", make_image(tmp_path), 4321, tmp_path / "out")


def test_extract_process_memory_surfaces_nonzero_exit(tmp_path, monkeypatch):
    def fake_run(cmd, capture_output, text, timeout):
        return subprocess.CompletedProcess(
            cmd, returncode=1, stdout="", stderr="translation layer error"
        )

    monkeypatch.setattr(va.subprocess, "run", fake_run)
    with pytest.raises(AnalysisError, match="failed for PID 4321"):
        va.extract_process_memory("vol", make_image(tmp_path), 4321, tmp_path / "out")


def test_extract_process_memory_writes_expected_filename(tmp_path, monkeypatch):
    def fake_run(cmd, capture_output, text, timeout):
        # cmd: [vol, -q, -o, outdir, -f, image, -r, json, windows.memmap.Memmap, --pid, "4321", --dump]
        out_dir = cmd[cmd.index("-o") + 1]
        (Path(out_dir) / "pid.4321.dmp").write_bytes(b"extracted process bytes")
        return subprocess.CompletedProcess(cmd, returncode=0, stdout="[]", stderr="")

    monkeypatch.setattr(va.subprocess, "run", fake_run)
    result_path = va.extract_process_memory("vol", make_image(tmp_path), 4321, tmp_path / "out")
    assert result_path.name == "pid.4321.dmp"
    assert result_path.read_bytes() == b"extracted process bytes"


def test_extract_target_process_end_to_end_with_discovery(tmp_path, monkeypatch):
    monkeypatch.setattr(va.shutil, "which", lambda name: f"/usr/bin/{name}")
    _mock_pslist(monkeypatch, [{"PID": 4321, "PPID": 500, "ImageFileName": "firefox.exe"}])

    def fake_extract(vol_bin, image_path, pid, output_dir, timeout=va.PLUGIN_TIMEOUT_SECONDS):
        assert pid == 4321
        output_dir.mkdir(parents=True, exist_ok=True)
        path = output_dir / f"pid.{pid}.dmp"
        path.write_bytes(b"data")
        return path

    monkeypatch.setattr(va, "extract_process_memory", fake_extract)
    result = va.extract_target_process(
        "vol", make_image(tmp_path), tmp_path / "out", process_name="firefox.exe"
    )
    assert result["status"] == "ok"
    assert result["pid"] == 4321
    assert result["dump_path"].endswith("pid.4321.dmp")
    assert result["source_image"] == str(make_image(tmp_path))


def test_extract_target_process_explicit_pid_skips_discovery(tmp_path, monkeypatch):
    monkeypatch.setattr(va.shutil, "which", lambda name: f"/usr/bin/{name}")

    def fail_find(*a, **k):
        raise AssertionError("discovery should be skipped when pid is given explicitly")

    monkeypatch.setattr(va, "find_process_pid", fail_find)

    def fake_extract(vol_bin, image_path, pid, output_dir, timeout=va.PLUGIN_TIMEOUT_SECONDS):
        output_dir.mkdir(parents=True, exist_ok=True)
        path = output_dir / f"pid.{pid}.dmp"
        path.write_bytes(b"data")
        return path

    monkeypatch.setattr(va, "extract_process_memory", fake_extract)
    result = va.extract_target_process("vol", make_image(tmp_path), tmp_path / "out", pid=999)
    assert result["status"] == "ok"
    assert result["pid"] == 999
    assert result["discovery"]["chosen_reason"] == "explicit PID override"


def test_extract_target_process_not_found_does_not_raise(tmp_path, monkeypatch):
    monkeypatch.setattr(va.shutil, "which", lambda name: f"/usr/bin/{name}")
    _mock_pslist(monkeypatch, [])
    result = va.extract_target_process("vol", make_image(tmp_path), tmp_path / "out")
    assert result["status"] == "not_found"
    assert result["dump_path"] is None


def test_extract_target_process_missing_image_raises(tmp_path):
    with pytest.raises(AnalysisError, match="not found"):
        va.extract_target_process("vol", tmp_path / "nope.raw", tmp_path / "out")
