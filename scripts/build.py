"""Build TRANCE's release packages. Used by .github/workflows/release.yml and by hand.

    python scripts/build.py acquire           Windows only: packaging/acquire/trance-acquire.exe
                                              + .sha256 (shipped inside the app by the next step)
    python scripts/build.py app               dist/TRANCE/ from packaging/trance.spec, archived to
                                              dist/release/TRANCE-<version>-<os>-x64.(zip|tar.gz)
    python scripts/build.py smoke dist/TRANCE runs one small analysis with the packaged app

Needs requirements.txt, requirements-gui.txt and PyInstaller (requirements-dev.txt).
PyInstaller can't cross-compile: build each OS's package on that OS.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from core.version import __version__
from gui.build_inputs import (
    ACQUIRE_SCRIPT,
    DEFAULT_EXE_NAME,
    build_pyinstaller_argv,
    built_exe_path,
)
from gui.build_runner import sha256_of, sidecar_text

ACQUIRE_DIR = ROOT / "packaging" / "acquire"
SPEC = ROOT / "packaging" / "trance.spec"
DIST = ROOT / "dist"
SMOKE_ONION = "smoketestonionaddressxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx.onion"


def _os_name() -> str:
    if sys.platform == "win32":
        return "windows"
    if sys.platform.startswith("linux"):
        return "linux"
    sys.exit(f"Packaging for {sys.platform} is not supported yet (Windows and Linux only).")


def build_acquire() -> Path:
    if sys.platform != "win32":
        sys.exit(
            "trance-acquire.exe can only be built on Windows (PyInstaller can't cross-compile)."
        )
    with tempfile.TemporaryDirectory(prefix="trance_acquire_") as work:
        work = Path(work)
        argv = build_pyinstaller_argv(ACQUIRE_SCRIPT, work / "dist", work / "build", work / "spec")
        subprocess.run(argv, check=True, cwd=ROOT)
        ACQUIRE_DIR.mkdir(parents=True, exist_ok=True)
        exe = ACQUIRE_DIR / f"{DEFAULT_EXE_NAME}.exe"
        shutil.copy2(built_exe_path(work / "dist"), exe)
    _write_sidecar(exe)
    return exe


def _write_sidecar(path: Path) -> None:
    text = sidecar_text(sha256_of(path), path.name)
    path.with_name(path.name + ".sha256").write_text(text, encoding="utf-8", newline="\n")
    print(text, end="")


def build_app() -> Path:
    os_name = _os_name()
    # PyInstaller parses ldd's "lib => /path (0x...)" lines; a "(" in the path breaks that,
    # and Qt's libraries are then silently left out (the app fails to start).
    if os_name == "linux" and "(" in f"{sys.prefix}{ROOT}":
        sys.exit(
            "Build from a checkout and venv whose paths have no parentheses: PyInstaller "
            f"misreads ldd output for them.\n  repo: {ROOT}\n  venv: {sys.prefix}"
        )
    if not (ACQUIRE_DIR / f"{DEFAULT_EXE_NAME}.exe").is_file():
        print("[!] packaging/acquire/trance-acquire.exe not found: the app is built without it")
    subprocess.run(
        [
            sys.executable,
            "-m",
            "PyInstaller",
            str(SPEC),
            "--noconfirm",
            "--clean",
            "--distpath",
            str(DIST),
            "--workpath",
            str(ROOT / "build"),
        ],
        check=True,
        cwd=ROOT,
    )
    release = DIST / "release"
    release.mkdir(parents=True, exist_ok=True)
    base = release / f"TRANCE-{__version__}-{os_name}-x64"
    archive = shutil.make_archive(
        str(base), "zip" if os_name == "windows" else "gztar", root_dir=DIST, base_dir="TRANCE"
    )
    print(f"[*] {archive}")
    return Path(archive)


def smoke(app_dir: Path) -> None:
    """Analyse a synthetic memory image with the packaged app's own --run-analysis child
    (the path the GUI uses): proves the frozen imports, templates, tz data and the memory
    scan's process pool work, without needing real evidence."""
    exe = app_dir / ("TRANCE.exe" if sys.platform == "win32" else "TRANCE")
    with tempfile.TemporaryDirectory(prefix="trance_smoke_") as tmp:
        tmp = Path(tmp)
        dump = tmp / "evidence" / "fullmem_20261014T000000Z.raw"
        dump.parent.mkdir()
        needle = f"http://{SMOKE_ONION}/login\x00session=abc123\x00".encode()
        # 96 MiB (mostly sparse) is above the size where the scan uses its process pool.
        with open(dump, "wb") as stream:
            stream.write(needle)
            stream.truncate(96 * 1024 * 1024 - len(needle))
            stream.seek(0, os.SEEK_END)
            stream.write(needle)
        request = {
            "case_name": "smoke",
            "output_dir": str(tmp / "out"),
            "overrides": {"dump": str(dump)},
            "source_type": "full-memory",
            "onion": SMOKE_ONION,
        }
        request_path = tmp / "request.json"
        request_path.write_text(json.dumps(request), encoding="utf-8")

        proc = subprocess.run(
            [str(exe), "--run-analysis", str(request_path)],
            capture_output=True,
            text=True,
            timeout=600,
        )
        print(proc.stdout)
        print(proc.stderr, file=sys.stderr)
        case = tmp / "out" / "smoke"
        problems = []
        if proc.returncode != 0:
            problems.append(f"exit code {proc.returncode}")
        if '@@TRANCE {"type": "result"' not in proc.stdout:
            problems.append("no result line on stdout")
        for name in ("findings.json", "report.html", "custody.json"):
            if not (case / name).is_file():
                problems.append(f"{name} was not written")
        if not problems:
            findings = json.loads((case / "findings.json").read_text(encoding="utf-8"))
            status = findings["modules"]["module_c_memory"]["status"]
            if status != "ok":
                problems.append(f"memory module status {status!r}")
            if SMOKE_ONION not in (case / "report.html").read_text(encoding="utf-8"):
                problems.append("the planted onion address is not in the report")
            libraries = findings["provenance"]["runtime"]["libraries"]
            missing = [name for name in ("regipy", "jinja2", "PySide6") if not libraries.get(name)]
            if missing:
                problems.append(f"no version recorded for {', '.join(missing)} (metadata)")
        problems += _gui_starts(exe, tmp / "out")
        problems += _vol_finds_plugins(exe.with_name(exe.name.replace("TRANCE", "vol")))
        if problems:
            sys.exit("Smoke test FAILED: " + "; ".join(problems))
    print("Smoke test passed.")


def _vol_finds_plugins(vol: Path) -> list[str]:
    """Volatility3 lists its plugins in --help only if it found them on disk."""
    if not vol.is_file():
        return [f"{vol.name} is missing from the package"]
    proc = subprocess.run([str(vol), "-h"], capture_output=True, text=True, timeout=300)
    missing = [
        p for p in ("windows.psscan", "windows.netscan", "windows.filescan") if p not in proc.stdout
    ]
    if missing:
        print(proc.stdout[-2000:], proc.stderr[-2000:])
        return [f"{vol.name} does not list {', '.join(missing)}"]
    return []


def _gui_starts(exe: Path, output_dir: Path, seconds: int = 20) -> list[str]:
    """The window (with its report view) must still be up after a while: a missing Qt
    library or plugin ends the process within a second or two."""
    env = {**os.environ, "QT_QPA_PLATFORM": "offscreen"}
    proc = subprocess.Popen(
        [str(exe), "--output-dir", str(output_dir)],
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    try:
        out, _ = proc.communicate(timeout=seconds)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.communicate()
        return []
    print(out)
    return [f"the GUI exited after start with code {proc.returncode}"]


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("acquire")
    sub.add_parser("app")
    smoke_parser = sub.add_parser("smoke")
    smoke_parser.add_argument("app_dir", type=Path, nargs="?", default=DIST / "TRANCE")
    args = parser.parse_args()
    if args.command == "acquire":
        build_acquire()
    elif args.command == "app":
        build_app()
    else:
        smoke(args.app_dir)


if __name__ == "__main__":
    main()
