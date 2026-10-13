"""Import an evidence folder from removable media into TRANCE's own case storage.

    <output-dir>/imported-evidence/<folder>_<UTC stamp>/
        evidence/            byte-for-byte copy of the chosen folder, made read-only
        import_record.json   where it came from, every file's SHA-256, the integrity check

Why copy at all: the evidence drive came back from a possibly compromised machine. Analysing
it in place keeps an untrusted device mounted for the whole run and lets nothing tell a later
change apart from the original. The copy is taken once, verified against the acquisition's own
hash records (core.evidence_integrity), then made read-only -- after which the drive can be
unplugged and the analysis runs entirely from the examiner's own disk.

The source is only ever opened for reading: no file on it is created, changed, renamed or
deleted, and timestamps are copied *onto* the copy, never the other way. (Reading a file can
still update its last-access time if the drive is mounted with atime; mount it read-only /
noatime to avoid even that -- see scripts/examiner-setup.sh.)

Qt-free and unit-tested; gui/import_worker.py runs it on a thread for the Analyse tab.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import stat
import sys
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from core.evidence_integrity import STATUS_FAILED, verify_evidence

IMPORT_DIRNAME = "imported-evidence"
EVIDENCE_SUBDIR = "evidence"
RECORD_NAME = "import_record.json"
CHUNK = 1024 * 1024

ProgressCallback = Callable[[str, int, int], None]  # (current file, bytes done, bytes total)


class EvidenceImportError(Exception):
    """The import could not be done (bad source/destination, unreadable file, bad copy)."""


class ImportCancelled(Exception):
    """The examiner cancelled; the partial copy has been removed."""


@dataclass
class ImportResult:
    destination: Path
    evidence_dir: Path
    files_copied: int
    bytes_copied: int
    skipped: list[str] = field(default_factory=list)
    integrity: dict = field(default_factory=dict)
    read_only: bool = False

    @property
    def integrity_failed(self) -> bool:
        return self.integrity.get("status") == STATUS_FAILED

    @property
    def safe_to_unplug(self) -> bool:
        # Every source file has been read and closed by the time a result exists.
        return True


def store_root(output_dir: Path) -> Path:
    return Path(output_dir) / IMPORT_DIRNAME


def _stamp(now: datetime | None = None) -> str:
    return (now or datetime.now(timezone.utc)).strftime("%Y%m%dT%H%M%SZ")


def destination_for(source: Path, store: Path, now: datetime | None = None) -> Path:
    name = re.sub(r"[^A-Za-z0-9._-]+", "_", Path(source).name).strip("._") or "evidence"
    return Path(store) / f"{name}_{_stamp(now)}"


def check_import(source: Path, destination: Path) -> list[str]:
    """Blocking problems; an empty list means the import may start."""
    problems = []
    source = Path(source)
    if not source.is_dir():
        problems.append(f"Evidence folder not found: {source}")
        return problems
    if source.is_symlink():
        problems.append(f"The evidence folder is a symbolic link: {source}")
    destination = Path(destination)
    if destination.exists() and (not destination.is_dir() or any(destination.iterdir())):
        problems.append(f"Destination already exists and is not empty: {destination}")
    src, dst = source.resolve(), destination.resolve()
    if dst.is_relative_to(src):
        problems.append("The case storage folder is inside the evidence folder.")
    if src.is_relative_to(dst):
        problems.append("The evidence folder is inside the case storage folder.")
    return problems


def _plan(source: Path) -> tuple[list[Path], list[Path], list[str], int]:
    """(directories, regular files, skipped entries, total bytes), never following links."""
    dirs: list[Path] = []
    files: list[Path] = []
    skipped: list[str] = []
    total = 0
    for current, dirnames, filenames in os.walk(source, followlinks=False):
        here = Path(current)
        for name in list(dirnames):
            path = here / name
            if path.is_symlink() or _is_junction(path):
                skipped.append(f"{path.relative_to(source).as_posix()} (link, not followed)")
                dirnames.remove(name)
            else:
                dirs.append(path)
        for name in filenames:
            path = here / name
            info = os.lstat(path)
            if stat.S_ISLNK(info.st_mode):
                skipped.append(f"{path.relative_to(source).as_posix()} (link, not followed)")
            elif not stat.S_ISREG(info.st_mode):
                skipped.append(f"{path.relative_to(source).as_posix()} (not a regular file)")
            else:
                files.append(path)
                total += info.st_size
    return sorted(dirs), sorted(files), skipped, total


def _is_junction(path: Path) -> bool:
    is_junction = getattr(os.path, "isjunction", None)
    return bool(is_junction and is_junction(path))


def _open_source(path: Path) -> int:
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    return os.open(path, flags)


class _Progress:
    """Running byte count across all files, reported through the caller's callback."""

    def __init__(self, callback: ProgressCallback, total: int):
        self._callback = callback
        self._total = total
        self._name = ""
        self.done = 0

    def start(self, name: str) -> None:
        self._name = name
        self._callback(name, self.done, self._total)

    def advance(self, size: int) -> None:
        self.done += size
        self._callback(self._name, self.done, self._total)


def _copy_file(
    source: Path,
    target: Path,
    on_chunk: Callable[[int], None],
    should_cancel: Callable[[], bool],
) -> str:
    """Copy one file, hashing the bytes as they are read; never overwrites (mode 'xb')."""
    digest = hashlib.sha256()
    fd = _open_source(source)
    with os.fdopen(fd, "rb") as src, open(target, "xb") as dst:
        while True:
            if should_cancel():
                raise ImportCancelled()
            chunk = src.read(CHUNK)
            if not chunk:
                break
            digest.update(chunk)
            dst.write(chunk)
            on_chunk(len(chunk))
        dst.flush()
        os.fsync(dst.fileno())
    info = os.stat(source)
    os.utime(target, ns=(info.st_atime_ns, info.st_mtime_ns))  # onto the copy only
    return digest.hexdigest()


def _hash(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as stream:
        for chunk in iter(lambda: stream.read(CHUNK), b""):
            digest.update(chunk)
    return digest.hexdigest()


def make_read_only(root: Path) -> None:
    """Files read-only everywhere; folders too on POSIX (a Windows folder's read-only flag
    does not stop changes inside it, so it is left alone there)."""
    for current, dirnames, filenames in os.walk(root, topdown=False):
        here = Path(current)
        for name in filenames:
            os.chmod(here / name, stat.S_IREAD | stat.S_IRGRP | stat.S_IROTH)
        if sys.platform != "win32":
            for name in dirnames:
                os.chmod(here / name, 0o555)
    if sys.platform != "win32":
        os.chmod(root, 0o555)


def _remove_partial(destination: Path) -> None:
    """Only ever called on the folder this import created."""

    def _writable_then_retry(function, path, _exc_info):
        for target in (os.path.dirname(path), path):
            os.chmod(target, stat.S_IWRITE | stat.S_IREAD | stat.S_IEXEC)
        function(path)

    if destination.exists():
        if sys.version_info >= (3, 12):
            shutil.rmtree(destination, onexc=_writable_then_retry)
        else:  # pragma: no cover - older interpreters
            shutil.rmtree(destination, onerror=_writable_then_retry)


def import_evidence(
    source: Path,
    store: Path,
    on_progress: ProgressCallback | None = None,
    should_cancel: Callable[[], bool] | None = None,
    now: datetime | None = None,
) -> ImportResult:
    source = Path(source)
    destination = destination_for(source, store, now)
    problems = check_import(source, destination)
    if problems:
        raise EvidenceImportError("\n".join(problems))
    cancelled = should_cancel or (lambda: False)
    progress = on_progress or (lambda *_: None)

    dirs, files, skipped, total = _plan(source.resolve())
    root = source.resolve()
    evidence_dir = destination / EVIDENCE_SUBDIR
    started = datetime.now(timezone.utc).isoformat()
    created = not destination.exists()
    destination.mkdir(parents=True, exist_ok=True)
    try:
        evidence_dir.mkdir()
        for directory in dirs:
            (evidence_dir / directory.relative_to(root)).mkdir(parents=True, exist_ok=True)
        tracker = _Progress(progress, total)
        copied: dict[str, str] = {}
        for path in files:
            relative = path.relative_to(root)
            name = relative.as_posix()
            tracker.start(name)
            try:
                digest = _copy_file(path, evidence_dir / relative, tracker.advance, cancelled)
            except ImportCancelled:
                raise
            except OSError as exc:
                raise EvidenceImportError(f"Could not copy {name}: {exc}") from exc
            if _hash(evidence_dir / relative) != digest:
                raise EvidenceImportError(
                    f"The copy of {name} does not match what was read from the drive -- "
                    "the destination disk may be failing."
                )
            copied[name] = digest
        done = tracker.done

        tracker.start("verifying acquisition hashes")
        integrity = verify_evidence(evidence_dir)
        record = {
            "source": str(source),
            "destination": str(evidence_dir),
            "started_at": started,
            "finished_at": datetime.now(timezone.utc).isoformat(),
            "files": copied,
            "bytes": done,
            "skipped": skipped,
            "integrity": integrity,
        }
        (destination / RECORD_NAME).write_text(json.dumps(record, indent=2), encoding="utf-8")
        make_read_only(destination)
    except BaseException:
        # Remove only what this import created: the whole folder if it made it, otherwise
        # (an empty folder was already there) just the copy and the record inside it.
        if created:
            _remove_partial(destination)
        else:
            _remove_partial(evidence_dir)
            (destination / RECORD_NAME).unlink(missing_ok=True)
        raise

    return ImportResult(
        destination=destination,
        evidence_dir=evidence_dir,
        files_copied=len(copied),
        bytes_copied=done,
        skipped=skipped,
        integrity=integrity,
        read_only=True,
    )
