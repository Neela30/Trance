"""Build trance-acquire.exe and lay out the tools bundle -- the Build tab's logic, Qt-free
(gui/build_worker.py only runs it on a thread and turns its output into signals).

    <output parent>/trance-acquire-<UTC stamp>/
        trance-acquire.exe
        trance-acquire.exe.sha256        "<sha256>  trance-acquire.exe" (sha256sum format)
        <winpmem>.exe + .sha256          only if a WinPMEM binary was picked

and, if a copy destination was picked (the write-protectable tools drive), the same folder
again under it, every copied file re-hashed against the original.

PyInstaller runs as a child process into a private temp folder; only the finished exe leaves
it. Every folder this writes is new: it refuses to start if a destination folder already
exists and isn't empty, files are created exclusively (never overwriting anything), and on
failure or cancel it removes only the folders it created itself.
"""

from __future__ import annotations

import hashlib
import shutil
import subprocess
import sys
import tempfile
import threading
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from gui.build_inputs import (
    ACQUIRE_SCRIPT,
    DEFAULT_EXE_NAME,
    build_pyinstaller_argv,
    built_exe_path,
)

CHUNK = 1024 * 1024


class BuildError(Exception):
    pass


class BuildCancelled(Exception):
    pass


@dataclass
class BuildResult:
    output_dir: Path
    exe_path: Path
    sha256: str
    sha256_path: Path
    winpmem_path: Path | None = None
    copy_dir: Path | None = None
    copied_files: list[Path] = field(default_factory=list)


def sha256_of(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as stream:
        for chunk in iter(lambda: stream.read(CHUNK), b""):
            digest.update(chunk)
    return digest.hexdigest()


def sidecar_text(digest: str, name: str) -> str:
    return f"{digest}  {name}\n"


def bundle_name(now: datetime | None = None) -> str:
    stamp = (now or datetime.now(timezone.utc)).strftime("%Y%m%dT%H%M%SZ")
    return f"{DEFAULT_EXE_NAME}-{stamp}"


def _folder_conflict(folder: Path) -> str | None:
    if folder.exists() and (not folder.is_dir() or any(folder.iterdir())):
        return f"Folder already exists and is not empty: {folder}"
    return None


def _copy_new(source: Path, target: Path) -> None:
    """Copy into a file that must not exist yet ('xb'), then carry the timestamps over."""
    with open(source, "rb") as src, open(target, "xb") as dst:
        shutil.copyfileobj(src, dst, CHUNK)
    shutil.copystat(source, target)


class BuildJob:
    def __init__(
        self,
        output_parent: Path,
        copy_to: Path | None = None,
        winpmem: Path | None = None,
        script: Path = ACQUIRE_SCRIPT,
        exe_name: str = DEFAULT_EXE_NAME,
        popen: Callable[..., subprocess.Popen] = subprocess.Popen,
        now: datetime | None = None,
    ):
        self.script = Path(script)
        self.exe_name = exe_name
        self.winpmem = Path(winpmem) if winpmem else None
        name = bundle_name(now)
        self.output_dir = Path(output_parent) / name
        self.copy_dir = Path(copy_to) / name if copy_to else None
        self._popen = popen
        self._proc: subprocess.Popen | None = None
        self._cancelled = threading.Event()

    def preflight(self) -> list[str]:
        """Blocking problems with the chosen folders/files; empty = OK to build."""
        problems = []
        if not self.script.is_file():
            problems.append(f"Acquisition script not found: {self.script}")
        for folder in (self.output_dir, self.copy_dir):
            if folder is not None and (conflict := _folder_conflict(folder)):
                problems.append(conflict)
        if self.copy_dir is not None and not self.copy_dir.parent.is_dir():
            problems.append(f"Copy destination not found: {self.copy_dir.parent}")
        if self.winpmem is not None and not self.winpmem.is_file():
            problems.append(f"WinPMEM binary not found: {self.winpmem}")
        if self.winpmem is not None and self.winpmem.name.lower() == f"{self.exe_name}.exe":
            problems.append("The WinPMEM binary can't have the same name as the acquisition exe.")
        return problems

    def cancel(self) -> None:
        self._cancelled.set()
        proc = self._proc
        if proc is not None and proc.poll() is None:
            proc.terminate()

    def run(self, on_line: Callable[[str], None] = lambda _line: None) -> BuildResult:
        problems = self.preflight()
        if problems:
            raise BuildError("\n".join(problems))
        work = Path(tempfile.mkdtemp(prefix="trance_build_"))
        created: list[Path] = []
        try:
            exe = self._pyinstaller(work, on_line)
            result = self._bundle(exe, created, on_line)
            if self.copy_dir is not None:
                self._copy_bundle(result, created, on_line)
            return result
        except BaseException:
            for folder in reversed(created):  # only folders this build made
                shutil.rmtree(folder, ignore_errors=True)
            raise
        finally:
            shutil.rmtree(work, ignore_errors=True)

    # -- steps --------------------------------------------------------------------

    def _pyinstaller(self, work: Path, on_line: Callable[[str], None]) -> Path:
        dist = work / "dist"
        argv = build_pyinstaller_argv(
            self.script, dist, work / "build", work / "spec", exe_name=self.exe_name
        )
        on_line("[*] " + " ".join(argv))
        if self._cancelled.is_set():
            raise BuildCancelled()
        creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0) if sys.platform == "win32" else 0
        self._proc = self._popen(
            argv,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
            cwd=str(self.script.parent),
            creationflags=creationflags,
        )
        for line in self._proc.stdout:
            on_line(line.rstrip())
        return_code = self._proc.wait()
        if self._cancelled.is_set():
            raise BuildCancelled()
        if return_code != 0:
            raise BuildError(f"PyInstaller exited with code {return_code}.")
        exe = built_exe_path(dist, self.exe_name)
        if not exe.is_file():
            raise BuildError(f"Build reported success but no exe was found at {exe}.")
        return exe

    def _bundle(self, exe: Path, created: list[Path], on_line) -> BuildResult:
        self._make_folder(self.output_dir, created)
        target = self.output_dir / exe.name
        _copy_new(exe, target)
        digest = sha256_of(target)
        sidecar = target.with_name(target.name + ".sha256")
        with open(sidecar, "x", encoding="utf-8", newline="\n") as stream:
            stream.write(sidecar_text(digest, target.name))
        on_line(f"[*] {target.name}: SHA-256 {digest}")
        result = BuildResult(
            output_dir=self.output_dir, exe_path=target, sha256=digest, sha256_path=sidecar
        )
        if self.winpmem is not None:
            pmem = self.output_dir / self.winpmem.name
            _copy_new(self.winpmem, pmem)
            pmem_digest = sha256_of(pmem)
            if pmem_digest != sha256_of(self.winpmem):
                raise BuildError(f"Copy of {self.winpmem.name} does not match the original.")
            pmem_sidecar = pmem.with_name(pmem.name + ".sha256")
            with open(pmem_sidecar, "x", encoding="utf-8", newline="\n") as stream:
                stream.write(sidecar_text(pmem_digest, pmem.name))
            on_line(f"[*] {pmem.name}: SHA-256 {pmem_digest}")
            result.winpmem_path = pmem
        on_line(f"[*] saved to {self.output_dir}")
        return result

    def _copy_bundle(self, result: BuildResult, created: list[Path], on_line) -> None:
        self._make_folder(self.copy_dir, created)
        for source in sorted(result.output_dir.iterdir()):
            if self._cancelled.is_set():
                raise BuildCancelled()
            target = self.copy_dir / source.name
            _copy_new(source, target)
            if sha256_of(target) != sha256_of(source):
                raise BuildError(
                    f"The copy of {source.name} on {self.copy_dir} does not match the "
                    "original; the drive may be failing."
                )
            result.copied_files.append(target)
        result.copy_dir = self.copy_dir
        on_line(f"[*] copied and verified {len(result.copied_files)} file(s) to {self.copy_dir}")

    def _make_folder(self, folder: Path, created: list[Path]) -> None:
        conflict = _folder_conflict(folder)
        if conflict:
            raise BuildError(conflict)
        if not folder.exists():
            folder.mkdir(parents=True)
            created.append(folder)
