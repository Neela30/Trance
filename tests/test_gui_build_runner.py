"""gui/build_runner.py with PyInstaller mocked: a fake Popen that "builds" by writing the exe
where --distpath says. No real build, no Qt."""

import hashlib
import io
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import ClassVar

import pytest

from gui import build_inputs
from gui.build_runner import BuildCancelled, BuildError, BuildJob, sidecar_text

NOW = datetime(2026, 10, 13, 9, 30, 0, tzinfo=timezone.utc)
BUNDLE = "trance-acquire-20261013T093000Z"
EXE_BYTES = b"MZ built exe"


class FakePopen:
    """Stands in for subprocess.Popen(python -m PyInstaller ...)."""

    instances: ClassVar[list["FakePopen"]] = []

    def __init__(self, argv, returncode=0, write_exe=True, lines=("building...",), **kwargs):
        self.argv = argv
        self.kwargs = kwargs
        self.returncode = returncode
        self.stdout = io.StringIO("".join(f"{line}\n" for line in lines))
        self.terminated = False
        if write_exe and returncode == 0:
            dist = Path(argv[argv.index("--distpath") + 1])
            dist.mkdir(parents=True)
            (dist / f"{argv[argv.index('--name') + 1]}.exe").write_bytes(EXE_BYTES)
        FakePopen.instances.append(self)

    def poll(self):
        return None

    def wait(self):
        return self.returncode

    def terminate(self):
        self.terminated = True


def popen_factory(**behaviour):
    return lambda argv, **kwargs: FakePopen(argv, **behaviour, **kwargs)


@pytest.fixture
def script(tmp_path):
    path = tmp_path / "src" / "acquire_all.py"
    path.parent.mkdir()
    path.write_text("# acquire")
    return path


def _job(tmp_path, script, **kwargs):
    kwargs.setdefault("popen", popen_factory())
    return BuildJob(tmp_path / "builds", script=script, now=NOW, **kwargs)


def test_build_writes_exe_and_sha256_sidecar_into_a_new_folder(tmp_path, script):
    lines = []
    result = _job(tmp_path, script).run(lines.append)

    folder = tmp_path / "builds" / BUNDLE
    assert result.output_dir == folder
    assert sorted(p.name for p in folder.iterdir()) == [
        "trance-acquire.exe",
        "trance-acquire.exe.sha256",
    ]
    digest = hashlib.sha256(EXE_BYTES).hexdigest()
    assert result.sha256 == digest
    assert (folder / "trance-acquire.exe.sha256").read_text() == f"{digest}  trance-acquire.exe\n"
    assert "building..." in lines  # PyInstaller's own output reaches the live log


def test_pyinstaller_is_run_with_the_documented_flags(tmp_path, script):
    FakePopen.instances.clear()
    _job(tmp_path, script).run()

    argv = FakePopen.instances[-1].argv
    assert argv[:3] == [sys.executable, "-m", "PyInstaller"]
    assert "--onefile" in argv
    assert argv[argv.index("--name") + 1] == "trance-acquire"
    assert argv[-1] == str(script)
    # Everything PyInstaller writes goes to a private temp folder, never next to the script.
    work = Path(argv[argv.index("--workpath") + 1])
    assert not work.is_relative_to(script.parent)
    assert not work.exists()  # cleaned up afterwards


def test_copy_to_tools_drive_with_winpmem_is_verified(tmp_path, script):
    drive = tmp_path / "tools_drive"
    drive.mkdir()
    (drive / "unrelated.txt").write_text("keep me")
    winpmem = tmp_path / "winpmem_mini_x64.exe"
    winpmem.write_bytes(b"pmem")

    result = _job(tmp_path, script, copy_to=drive, winpmem=winpmem).run()

    copy = drive / BUNDLE
    assert result.copy_dir == copy
    names = sorted(p.name for p in copy.iterdir())
    assert names == [
        "trance-acquire.exe",
        "trance-acquire.exe.sha256",
        "winpmem_mini_x64.exe",
        "winpmem_mini_x64.exe.sha256",
    ]
    for name in names:
        assert (copy / name).read_bytes() == (result.output_dir / name).read_bytes()
    assert (copy / "winpmem_mini_x64.exe.sha256").read_text() == sidecar_text(
        hashlib.sha256(b"pmem").hexdigest(), "winpmem_mini_x64.exe"
    )
    assert (drive / "unrelated.txt").read_text() == "keep me"  # nothing else touched
    assert winpmem.read_bytes() == b"pmem"
    for sidecar in copy.glob("*.sha256"):  # LF only, so `sha256sum -c` accepts them
        assert b"\r" not in sidecar.read_bytes()


def test_refuses_to_start_when_a_destination_folder_is_not_empty(tmp_path, script):
    existing = tmp_path / "builds" / BUNDLE
    existing.mkdir(parents=True)
    (existing / "trance-acquire.exe").write_bytes(b"older build")
    job = _job(tmp_path, script, popen=lambda *a, **k: pytest.fail("PyInstaller must not run"))

    assert any("not empty" in p for p in job.preflight())
    with pytest.raises(BuildError, match="not empty"):
        job.run()
    assert (existing / "trance-acquire.exe").read_bytes() == b"older build"


def test_preflight_reports_missing_inputs(tmp_path, script):
    job = _job(
        tmp_path,
        script,
        copy_to=tmp_path / "no_such_drive",
        winpmem=tmp_path / "missing_winpmem.exe",
    )
    problems = job.preflight()
    assert any("Copy destination not found" in p for p in problems)
    assert any("WinPMEM binary not found" in p for p in problems)


def test_pyinstaller_failure_keeps_nothing(tmp_path, script):
    with pytest.raises(BuildError, match="exited with code 1"):
        _job(tmp_path, script, popen=popen_factory(returncode=1)).run()
    assert not (tmp_path / "builds" / BUNDLE).exists()


def test_missing_exe_after_success_is_an_error(tmp_path, script):
    with pytest.raises(BuildError, match="no exe was found"):
        _job(tmp_path, script, popen=popen_factory(write_exe=False)).run()


def test_cancel_terminates_pyinstaller_and_keeps_nothing(tmp_path, script):
    job = None

    class CancellingPopen(FakePopen):
        def wait(self):
            job.cancel()  # the examiner pressed Cancel mid-build
            return -15

    FakePopen.instances.clear()
    job = _job(tmp_path, script, popen=lambda argv, **kw: CancellingPopen(argv, **kw))
    with pytest.raises(BuildCancelled):
        job.run()
    assert FakePopen.instances[-1].terminated
    assert not (tmp_path / "builds" / BUNDLE).exists()


def test_failed_copy_removes_only_the_folders_this_build_created(tmp_path, script, monkeypatch):
    drive = tmp_path / "tools_drive"
    drive.mkdir()
    (drive / "unrelated.txt").write_text("keep me")
    calls = {"n": 0}
    from gui import build_runner

    real = build_runner.sha256_of

    def flaky(path):
        calls["n"] += 1
        if Path(path).is_relative_to(drive):
            return "0" * 64  # the copy on the drive reads back wrong
        return real(path)

    monkeypatch.setattr(build_runner, "sha256_of", flaky)
    with pytest.raises(BuildError, match="does not match"):
        _job(tmp_path, script, copy_to=drive).run()
    assert not (drive / BUNDLE).exists()
    assert not (tmp_path / "builds" / BUNDLE).exists()
    assert (drive / "unrelated.txt").read_text() == "keep me"


def test_build_is_disabled_off_windows_with_a_reason():
    ok, reason = build_inputs.build_support("linux")
    assert not ok and "cross-compile" in reason
    assert build_inputs.build_support("darwin")[0] is False


def test_build_supported_on_windows_from_source(monkeypatch):
    monkeypatch.delattr(sys, "frozen", raising=False)
    assert build_inputs.build_support("win32") == (True, "")


def test_frozen_app_cannot_build(monkeypatch):
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    ok, reason = build_inputs.build_support("win32")
    assert not ok and "source checkout" in reason


def test_elevation_warning_only_when_elevated(monkeypatch):
    monkeypatch.setattr(build_inputs, "is_elevated", lambda: True)
    assert "administrator" in build_inputs.elevation_warning()
    monkeypatch.setattr(build_inputs, "is_elevated", lambda: False)
    assert build_inputs.elevation_warning() is None


def _shipped_exe(folder: Path, data: bytes = EXE_BYTES, recorded: bytes = EXE_BYTES) -> Path:
    exe = folder / "acquire" / "trance-acquire.exe"
    exe.parent.mkdir(parents=True)
    exe.write_bytes(data)
    digest = hashlib.sha256(recorded).hexdigest()
    exe.with_name("trance-acquire.exe.sha256").write_text(sidecar_text(digest, exe.name))
    return exe


def test_prebuilt_exe_is_saved_without_running_pyinstaller(tmp_path, script):
    FakePopen.instances.clear()
    exe = _shipped_exe(tmp_path / "bundle")
    result = _job(tmp_path, script, prebuilt=exe).run()

    assert FakePopen.instances == []
    assert result.exe_path.read_bytes() == EXE_BYTES
    assert result.sha256 == hashlib.sha256(EXE_BYTES).hexdigest()
    assert result.sha256_path.is_file()


def test_damaged_prebuilt_exe_is_refused_and_nothing_kept(tmp_path, script):
    exe = _shipped_exe(tmp_path / "bundle", data=b"MZ tampered")
    with pytest.raises(BuildError, match="damaged"):
        _job(tmp_path, script, prebuilt=exe).run()
    assert not (tmp_path / "builds" / BUNDLE).exists()


def test_frozen_app_with_a_shipped_exe_can_save_it_on_any_os(tmp_path, monkeypatch):
    _shipped_exe(tmp_path)
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    monkeypatch.setattr(sys, "_MEIPASS", str(tmp_path), raising=False)
    assert build_inputs.bundled_acquire_exe() == tmp_path / "acquire" / "trance-acquire.exe"
    assert build_inputs.build_support("linux") == (True, "")
