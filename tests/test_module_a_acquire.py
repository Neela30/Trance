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
        return subprocess.CompletedProcess(
            cmd, returncode=1, stdout="", stderr="ERROR: Access is denied."
        )

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


def test_acquire_software_writes_sidecar_and_custody(tmp_path, monkeypatch):
    def fake_run(cmd, capture_output, text, timeout):
        assert cmd[:3] == ["reg", "save", "HKLM\\SOFTWARE"]
        out_path = cmd[3]
        with open(out_path, "wb") as f:
            f.write(b"fake SOFTWARE hive bytes")
        return subprocess.CompletedProcess(cmd, returncode=0, stdout="", stderr="")

    monkeypatch.setattr(acquire.subprocess, "run", fake_run)
    custody = acquire.CustodyLog(tmp_path / "custody.json")
    path = acquire.acquire_software(tmp_path, custody)

    assert path.read_bytes() == b"fake SOFTWARE hive bytes"
    sidecar = path.with_name(path.name + ".sha256")
    assert sidecar.exists()
    assert custody.entries[0].sha256 == acquire.hash_file(path)


def test_acquire_usrclass_writes_sidecar_and_custody(tmp_path, monkeypatch):
    captured = {}

    def fake_copy_via_shadow(relative_path, output_path, drive="C:"):
        captured["relative_path"] = relative_path
        output_path.write_bytes(b"fake usrclass bytes")

    monkeypatch.setattr(acquire, "_copy_via_shadow", fake_copy_via_shadow)
    custody = acquire.CustodyLog(tmp_path / "custody.json")
    path = acquire.acquire_usrclass("alice", tmp_path, custody)

    assert path.read_bytes() == b"fake usrclass bytes"
    assert captured["relative_path"] == r"Users\alice\AppData\Local\Microsoft\Windows\UsrClass.dat"
    sidecar = path.with_name(path.name + ".sha256")
    assert sidecar.exists()
    assert custody.entries[0].sha256 == acquire.hash_file(path)


def _raise_os_error(*_args, **_kwargs):
    raise OSError("no controlling terminal")


def test_resolve_target_user_prefers_explicit_ntuser_user():
    assert acquire._resolve_target_user("alice") == "alice"


def test_resolve_target_user_prefers_userprofile_folder_name_over_login_name(monkeypatch):
    # The real field bug: a long-lived Windows account's LOGIN name ("neela") had
    # diverged from its PROFILE FOLDER name ("Admin", i.e. C:\Users\Admin) -- Windows
    # never renames an existing profile folder when an account's login name changes
    # later. _copy_via_shadow() needs the folder name (it builds a literal filesystem
    # path), so os.getlogin()/USERNAME -- both login-name-based -- are the wrong kind of
    # value here even when they're internally consistent with each other and with
    # `reg save HKCU` (which needs no path at all). USERPROFILE must win regardless.
    monkeypatch.setenv("USERPROFILE", r"C:\Users\Admin")
    monkeypatch.setattr(acquire.os, "getlogin", lambda: "neela")
    monkeypatch.setenv("USERNAME", "neela")
    assert acquire._resolve_target_user(None) == "Admin"


def test_resolve_target_user_falls_back_to_os_getlogin_when_no_userprofile(monkeypatch):
    monkeypatch.delenv("USERPROFILE", raising=False)
    monkeypatch.setattr(acquire.os, "getlogin", lambda: "admin")
    monkeypatch.setenv("USERNAME", "neela")
    assert acquire._resolve_target_user(None) == "admin"


def test_resolve_target_user_falls_back_to_environment_when_getlogin_unavailable(monkeypatch):
    # os.getlogin() routinely raises OSError without a controlling terminal (e.g. a
    # non-Windows dev machine, or certain service contexts) -- USERNAME/USER still work
    # as a fallback in that case.
    monkeypatch.delenv("USERPROFILE", raising=False)
    monkeypatch.setattr(acquire.os, "getlogin", _raise_os_error)
    monkeypatch.setenv("USERNAME", "bob")
    monkeypatch.delenv("USER", raising=False)
    assert acquire._resolve_target_user(None) == "bob"


def test_resolve_target_user_raises_when_unresolvable(monkeypatch):
    import getpass

    monkeypatch.delenv("USERPROFILE", raising=False)
    monkeypatch.setattr(acquire.os, "getlogin", _raise_os_error)
    monkeypatch.delenv("USERNAME", raising=False)
    monkeypatch.delenv("USER", raising=False)
    monkeypatch.setattr(getpass, "getuser", _raise_os_error)
    with pytest.raises(AcquisitionError, match="Could not resolve the current username"):
        acquire._resolve_target_user(None)


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
        return subprocess.CompletedProcess(
            cmd, returncode=1, stdout="", stderr="Win32_ShadowCopy.Create failed"
        )

    monkeypatch.setattr(acquire.subprocess, "run", fake_run)
    with pytest.raises(AcquisitionError, match="Could not create a shadow copy"):
        acquire._create_shadow_copy()


def test_create_shadow_copy_rejects_unparseable_output(monkeypatch):
    def fake_run(cmd, capture_output, text, timeout):
        return subprocess.CompletedProcess(
            cmd, returncode=0, stdout="unexpected output shape", stderr=""
        )

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
        "vssadmin",
        "delete",
        "shadows",
        "/shadow={12345678-1234-1234-1234-1234567890ab}",
        "/quiet",
    ]


def test_delete_shadow_copy_keeps_braced_id_as_is(monkeypatch):
    captured = {}

    def fake_run(cmd, capture_output, text, timeout):
        captured["cmd"] = cmd
        return subprocess.CompletedProcess(cmd, returncode=0, stdout="", stderr="")

    monkeypatch.setattr(acquire.subprocess, "run", fake_run)
    acquire._delete_shadow_copy("{12345678-1234-1234-1234-1234567890ab}")
    assert captured["cmd"] == [
        "vssadmin",
        "delete",
        "shadows",
        "/shadow={12345678-1234-1234-1234-1234567890ab}",
        "/quiet",
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
        acquire._copy_via_shadow(
            r"Windows\AppCompat\Programs\Amcache.hve", tmp_path / "Amcache.hve"
        )

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
    assert results["SOFTWARE"]["status"] == "ok"
    assert results["UsrClass.dat"]["status"] == "ok"
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
    assert results["UsrClass.dat"]["status"] == "ok"
    # Both NTUSER.DAT and UsrClass.dat are acquired for the SAME named user --
    # "the target user" is one concept, not two separate flags (see
    # acquire._resolve_target_user()'s docstring).
    assert sum("alice" in c for c in calls) == 2


def test_cli_skip_flags(monkeypatch, tmp_path):
    monkeypatch.setattr(
        sys, "argv", ["acquire.py", "--output-dir", str(tmp_path), "--skip-amcache"]
    )
    monkeypatch.setattr(
        sys, "platform", "linux"
    )  # forces AcquisitionError -> clean exit 1, no real acquisition
    with pytest.raises(SystemExit) as exc_info:
        acquire.main()
    assert exc_info.value.code == 1


def test_cli_skip_usrclass_flag_is_parsed(monkeypatch, tmp_path):
    captured = {}

    def fake_acquire_all(output_dir, **kwargs):
        captured.update(kwargs)
        return {"custody_log_path": str(tmp_path / "custody.json")}

    monkeypatch.setattr(
        sys, "argv", ["acquire.py", "--output-dir", str(tmp_path), "--skip-usrclass"]
    )
    monkeypatch.setattr(acquire, "acquire_all", fake_acquire_all)
    acquire.main()

    assert captured["include_usrclass"] is False
