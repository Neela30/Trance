import subprocess
import sys

import pytest

from core.exceptions import AcquisitionError
from modules.module_a_registry import acquire


def test_acquire_all_refuses_on_non_windows(tmp_path, monkeypatch):
    monkeypatch.setattr(sys, "platform", "linux")
    with pytest.raises(AcquisitionError, match="only runs on Windows"):
        acquire.acquire_all(tmp_path)


def test_acquire_all_requires_elevation(tmp_path, monkeypatch):
    monkeypatch.setattr(sys, "platform", "win32")
    monkeypatch.setattr(acquire, "_is_admin", lambda: False)
    with pytest.raises(AcquisitionError, match="elevated"):
        acquire.acquire_all(tmp_path)


def _fake_run_factory(by_argv0: dict):
    def fake_run(cmd, capture_output, text, timeout):
        handler = by_argv0.get(cmd[0])
        if handler is None:
            raise AssertionError(f"unexpected command: {cmd}")
        return handler(cmd)

    return fake_run


def test_reg_save_surfaces_nonzero_exit(tmp_path, monkeypatch):
    def fake_run(cmd, capture_output, text, timeout):
        return subprocess.CompletedProcess(cmd, returncode=1, stdout="", stderr="ERROR: Access is denied.")

    monkeypatch.setattr(acquire.subprocess, "run", fake_run)
    with pytest.raises(AcquisitionError, match="failed \\(exit 1\\)"):
        acquire._reg_save("HKLM\\SYSTEM", tmp_path / "SYSTEM")


def test_reg_save_rejects_empty_output_despite_success_exit(tmp_path, monkeypatch):
    def fake_run(cmd, capture_output, text, timeout):
        return subprocess.CompletedProcess(cmd, returncode=0, stdout="", stderr="")

    monkeypatch.setattr(acquire.subprocess, "run", fake_run)
    with pytest.raises(AcquisitionError, match="no \\(or an empty\\)"):
        acquire._reg_save("HKCU", tmp_path / "NTUSER.DAT")


def test_acquire_system_writes_sidecar_and_custody(tmp_path, monkeypatch):
    def fake_run(cmd, capture_output, text, timeout):
        assert cmd[:2] == ["reg", "save"]
        out_path = cmd[3]
        with open(out_path, "wb") as f:
            f.write(b"fake SYSTEM hive bytes")
        return subprocess.CompletedProcess(cmd, returncode=0, stdout="", stderr="")

    monkeypatch.setattr(acquire.subprocess, "run", fake_run)
    custody = acquire.CustodyLog(tmp_path / "custody.json")
    path = acquire.acquire_system(tmp_path, custody)

    assert path.read_bytes() == b"fake SYSTEM hive bytes"
    sidecar = path.with_name(path.name + ".sha256")
    assert sidecar.exists()
    assert custody.entries[0].sha256 == acquire.hash_file(path)


def test_create_shadow_copy_parses_id_and_device_object(monkeypatch):
    # Real shape of the PowerShell/WMI script's stdout (Win32_ShadowCopy.Create(), not
    # vssadmin -- vssadmin's own "create shadow" verb is Server-only, confirmed on a real
    # client-Windows target: "Error: Invalid command").
    stdout = "ShadowID={12345678-1234-1234-1234-1234567890ab}\nDeviceObject=\\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy2\n"

    def fake_run(cmd, capture_output, text, timeout):
        assert cmd[0] == "powershell"
        return subprocess.CompletedProcess(cmd, returncode=0, stdout=stdout, stderr="")

    monkeypatch.setattr(acquire.subprocess, "run", fake_run)
    shadow_id, volume = acquire._create_shadow_copy()
    assert shadow_id == "{12345678-1234-1234-1234-1234567890ab}"
    assert volume == "\\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy2"


def test_create_shadow_copy_surfaces_nonzero_exit(monkeypatch):
    def fake_run(cmd, capture_output, text, timeout):
        return subprocess.CompletedProcess(cmd, returncode=1, stdout="", stderr="Win32_ShadowCopy.Create failed")

    monkeypatch.setattr(acquire.subprocess, "run", fake_run)
    with pytest.raises(AcquisitionError, match="Could not create a shadow copy"):
        acquire._create_shadow_copy()


def test_create_shadow_copy_rejects_unparseable_output(monkeypatch):
    def fake_run(cmd, capture_output, text, timeout):
        return subprocess.CompletedProcess(cmd, returncode=0, stdout="unexpected output shape", stderr="")

    monkeypatch.setattr(acquire.subprocess, "run", fake_run)
    with pytest.raises(AcquisitionError, match="didn't contain a recognizable"):
        acquire._create_shadow_copy()


def test_delete_shadow_copy_braces_a_bare_guid(monkeypatch):
    captured = {}

    def fake_run(cmd, capture_output, text, timeout):
        captured["cmd"] = cmd
        return subprocess.CompletedProcess(cmd, returncode=0, stdout="", stderr="")

    monkeypatch.setattr(acquire.subprocess, "run", fake_run)
    acquire._delete_shadow_copy("12345678-1234-1234-1234-1234567890ab")
    assert captured["cmd"] == [
        "vssadmin", "delete", "shadows", "/shadow={12345678-1234-1234-1234-1234567890ab}", "/quiet",
    ]


def test_delete_shadow_copy_keeps_braced_id_as_is(monkeypatch):
    captured = {}

    def fake_run(cmd, capture_output, text, timeout):
        captured["cmd"] = cmd
        return subprocess.CompletedProcess(cmd, returncode=0, stdout="", stderr="")

    monkeypatch.setattr(acquire.subprocess, "run", fake_run)
    acquire._delete_shadow_copy("{12345678-1234-1234-1234-1234567890ab}")
    assert captured["cmd"] == [
        "vssadmin", "delete", "shadows", "/shadow={12345678-1234-1234-1234-1234567890ab}", "/quiet",
    ]


def test_copy_via_shadow_deletes_shadow_even_on_copy_failure(tmp_path, monkeypatch):
    deleted = []

    def fake_create(drive="C:"):
        return "{shadow-id}", "\\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy3"

    def fake_delete(shadow_id):
        deleted.append(shadow_id)

    def fake_copyfile(source, dest):
        raise OSError("simulated copy failure")

    monkeypatch.setattr(acquire, "_create_shadow_copy", fake_create)
    monkeypatch.setattr(acquire, "_delete_shadow_copy", fake_delete)
    monkeypatch.setattr(acquire.shutil, "copyfile", fake_copyfile)

    with pytest.raises(AcquisitionError, match="Could not copy"):
        acquire._copy_via_shadow(r"Windows\AppCompat\Programs\Amcache.hve", tmp_path / "Amcache.hve")

    assert deleted == ["{shadow-id}"]


def test_copy_via_shadow_success_hashes_and_deletes_shadow(tmp_path, monkeypatch):
    deleted = []

    def fake_create(drive="C:"):
        return "{shadow-id}", "\\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy3"

    def fake_delete(shadow_id):
        deleted.append(shadow_id)

    def fake_copyfile(source, dest):
        with open(dest, "wb") as f:
            f.write(b"fake amcache bytes")

    monkeypatch.setattr(acquire, "_create_shadow_copy", fake_create)
    monkeypatch.setattr(acquire, "_delete_shadow_copy", fake_delete)
    monkeypatch.setattr(acquire.shutil, "copyfile", fake_copyfile)

    output_path = tmp_path / "Amcache.hve"
    acquire._copy_via_shadow(r"Windows\AppCompat\Programs\Amcache.hve", output_path)

    assert output_path.read_bytes() == b"fake amcache bytes"
    assert deleted == ["{shadow-id}"]


def test_acquire_all_isolates_one_hive_failure_from_the_rest(tmp_path, monkeypatch):
    monkeypatch.setattr(sys, "platform", "win32")
    monkeypatch.setattr(acquire, "_is_admin", lambda: True)

    def fake_reg_save(hive_key, output_path):
        if "SYSTEM" in hive_key:
            raise AcquisitionError("SYSTEM export failed")
        output_path.write_bytes(b"fake ntuser")

    def fake_copy_via_shadow(relative_path, output_path, drive="C:"):
        output_path.write_bytes(b"fake amcache")

    monkeypatch.setattr(acquire, "_reg_save", fake_reg_save)
    monkeypatch.setattr(acquire, "_copy_via_shadow", fake_copy_via_shadow)

    results = acquire.acquire_all(tmp_path)

    assert results["SYSTEM"]["status"] == "error"
    assert "SYSTEM export failed" in results["SYSTEM"]["message"]
    assert results["NTUSER.DAT"]["status"] == "ok"
    assert results["Amcache.hve"]["status"] == "ok"
    assert "custody_log_path" in results


def test_acquire_all_uses_named_user_for_ntuser_when_given(tmp_path, monkeypatch):
    monkeypatch.setattr(sys, "platform", "win32")
    monkeypatch.setattr(acquire, "_is_admin", lambda: True)

    calls = []

    def fake_copy_via_shadow(relative_path, output_path, drive="C:"):
        calls.append(relative_path)
        output_path.write_bytes(b"data")

    def fake_reg_save(hive_key, output_path):
        output_path.write_bytes(b"data")

    monkeypatch.setattr(acquire, "_copy_via_shadow", fake_copy_via_shadow)
    monkeypatch.setattr(acquire, "_reg_save", fake_reg_save)

    results = acquire.acquire_all(tmp_path, ntuser_user="alice")

    assert results["NTUSER.DAT"]["status"] == "ok"
    assert any("alice" in c for c in calls)


def test_cli_skip_flags(monkeypatch, tmp_path):
    monkeypatch.setattr(sys, "argv", ["acquire.py", "--output-dir", str(tmp_path), "--skip-amcache"])
    monkeypatch.setattr(sys, "platform", "linux")  # forces AcquisitionError -> clean exit 1, no real acquisition
    with pytest.raises(SystemExit) as exc_info:
        acquire.main()
    assert exc_info.value.code == 1
