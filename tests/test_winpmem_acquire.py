import subprocess
import sys

import pytest

from core.exceptions import AcquisitionError
from modules.module_c_memory import winpmem_acquire


def fake_winpmem_binary(tmp_path):
    binary = tmp_path / "winpmem.exe"
    binary.write_bytes(b"not a real binary, just needs to exist")
    return binary


def test_acquire_refuses_on_non_windows(tmp_path, monkeypatch):
    monkeypatch.setattr(sys, "platform", "linux")
    with pytest.raises(AcquisitionError, match="only runs on Windows"):
        winpmem_acquire.acquire(fake_winpmem_binary(tmp_path), tmp_path / "out")


def test_acquire_rejects_missing_winpmem_binary(tmp_path, monkeypatch):
    monkeypatch.setattr(sys, "platform", "win32")
    monkeypatch.setattr(winpmem_acquire, "_is_admin", lambda: True)
    with pytest.raises(AcquisitionError, match="not found"):
        winpmem_acquire.acquire(tmp_path / "does-not-exist.exe", tmp_path / "out")


def test_acquire_requires_elevation(tmp_path, monkeypatch):
    monkeypatch.setattr(sys, "platform", "win32")
    monkeypatch.setattr(winpmem_acquire, "_is_admin", lambda: False)
    with pytest.raises(AcquisitionError, match="elevated"):
        winpmem_acquire.acquire(fake_winpmem_binary(tmp_path), tmp_path / "out")


def test_acquire_surfaces_nonzero_exit(tmp_path, monkeypatch):
    monkeypatch.setattr(sys, "platform", "win32")
    monkeypatch.setattr(winpmem_acquire, "_is_admin", lambda: True)

    def fake_run(cmd, capture_output, text, timeout):
        return subprocess.CompletedProcess(cmd, returncode=1, stdout="", stderr="driver load failed")

    monkeypatch.setattr(winpmem_acquire.subprocess, "run", fake_run)
    with pytest.raises(AcquisitionError, match="exited with code 1"):
        winpmem_acquire.acquire(fake_winpmem_binary(tmp_path), tmp_path / "out")
    assert not list((tmp_path / "out").glob("*.raw"))


def test_acquire_rejects_empty_output_despite_success_exit(tmp_path, monkeypatch):
    monkeypatch.setattr(sys, "platform", "win32")
    monkeypatch.setattr(winpmem_acquire, "_is_admin", lambda: True)

    def fake_run(cmd, capture_output, text, timeout):
        # WinPMEM "succeeded" but never wrote the image (cmd[-1] is the output path).
        return subprocess.CompletedProcess(cmd, returncode=0, stdout="ok", stderr="")

    monkeypatch.setattr(winpmem_acquire.subprocess, "run", fake_run)
    with pytest.raises(AcquisitionError, match="empty"):
        winpmem_acquire.acquire(fake_winpmem_binary(tmp_path), tmp_path / "out")


def test_acquire_writes_image_sidecar_and_custody(tmp_path, monkeypatch):
    monkeypatch.setattr(sys, "platform", "win32")
    monkeypatch.setattr(winpmem_acquire, "_is_admin", lambda: True)

    payload = b"synthetic full-memory image bytes"

    def fake_run(cmd, capture_output, text, timeout):
        output_path = cmd[-1]
        with open(output_path, "wb") as f:
            f.write(payload)
        return subprocess.CompletedProcess(cmd, returncode=0, stdout="ok", stderr="")

    monkeypatch.setattr(winpmem_acquire.subprocess, "run", fake_run)
    output_dir = tmp_path / "out"
    image_path = winpmem_acquire.acquire(fake_winpmem_binary(tmp_path), output_dir)

    assert image_path.read_bytes() == payload
    sidecar = image_path.with_name(image_path.name + ".sha256")
    assert sidecar.exists()
    digest = sidecar.read_text().split()[0]
    assert digest == winpmem_acquire.hash_file(image_path)

    custody_files = list(output_dir.glob("*.custody.json"))
    assert len(custody_files) == 1
    assert "full-memory" in custody_files[0].read_text()


def test_run_winpmem_passes_extra_args_before_output_path(tmp_path, monkeypatch):
    captured = {}

    def fake_run(cmd, capture_output, text, timeout):
        captured["cmd"] = cmd
        return subprocess.CompletedProcess(cmd, returncode=0)

    monkeypatch.setattr(winpmem_acquire.subprocess, "run", fake_run)
    binary = fake_winpmem_binary(tmp_path)
    out = tmp_path / "img.raw"
    winpmem_acquire.run_winpmem(binary, out, ["-o"])
    assert captured["cmd"] == [str(binary), "-o", str(out)]


def test_run_winpmem_missing_binary_raises_acquisition_error(tmp_path):
    with pytest.raises(AcquisitionError, match="not found or not executable"):
        winpmem_acquire.run_winpmem(tmp_path / "nope.exe", tmp_path / "img.raw")


def test_cli_requires_winpmem_path(monkeypatch):
    monkeypatch.setattr(sys, "argv", ["winpmem_acquire.py"])
    with pytest.raises(SystemExit):
        winpmem_acquire.main()
