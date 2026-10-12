import sys
from pathlib import Path

from gui.build_inputs import (
    build_pyinstaller_argv,
    built_exe_path,
    check_prerequisites,
    default_output_name,
)


def test_default_output_name():
    assert default_output_name() == "trance-acquire.exe"


def test_check_prerequisites_flags_missing_script(tmp_path):
    missing = tmp_path / "does_not_exist.py"
    problems = check_prerequisites(missing)
    assert any("not found" in p for p in problems)


def test_check_prerequisites_ok_when_script_exists_and_tools_present(tmp_path, monkeypatch):
    script = tmp_path / "acquire_all.py"
    script.write_text("# stub")
    monkeypatch.setattr(sys, "maxsize", 2**63 - 1)
    monkeypatch.setattr("gui.build_inputs.importlib.util.find_spec", lambda name: object())

    assert check_prerequisites(script) == []


def test_check_prerequisites_flags_32bit_interpreter(tmp_path, monkeypatch):
    script = tmp_path / "acquire_all.py"
    script.write_text("# stub")
    monkeypatch.setattr(sys, "maxsize", 2**31 - 1)
    monkeypatch.setattr("gui.build_inputs.importlib.util.find_spec", lambda name: object())

    problems = check_prerequisites(script)
    assert any("32-bit" in p for p in problems)


def test_check_prerequisites_flags_missing_pyinstaller(tmp_path, monkeypatch):
    script = tmp_path / "acquire_all.py"
    script.write_text("# stub")
    monkeypatch.setattr(sys, "maxsize", 2**63 - 1)
    monkeypatch.setattr("gui.build_inputs.importlib.util.find_spec", lambda name: None)

    problems = check_prerequisites(script)
    assert any("PyInstaller is not installed" in p for p in problems)


def test_build_pyinstaller_argv_contains_expected_flags(tmp_path):
    script = tmp_path / "acquire_all.py"
    dist_dir = tmp_path / "dist"
    work_dir = tmp_path / "build"
    spec_dir = tmp_path / "spec"

    argv = build_pyinstaller_argv(script, dist_dir, work_dir, spec_dir, exe_name="trance-acquire")

    assert argv[0] == sys.executable
    assert argv[1:3] == ["-m", "PyInstaller"]
    assert "--onefile" in argv
    assert "--uac-admin" in argv
    assert "--name" in argv
    assert argv[argv.index("--name") + 1] == "trance-acquire"
    assert argv[argv.index("--distpath") + 1] == str(dist_dir)
    assert argv[argv.index("--workpath") + 1] == str(work_dir)
    assert argv[argv.index("--specpath") + 1] == str(spec_dir)
    assert argv[-1] == str(script)


def test_built_exe_path():
    assert built_exe_path(Path("dist"), "trance-acquire") == Path("dist/trance-acquire.exe")
