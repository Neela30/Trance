"""Whole-evidence-folder hash verification, run before any module parses anything.

Evidence comes off a machine that may be compromised, and travels on removable media. Every
acquisition step already writes hash records next to what it captured:

  <file>.sha256     one-line sidecar ("<sha256>  <name>"): registry hives, memory images,
                    and acquire_manifest.json itself
  hashes.sha256     sha256sum-format list of relative paths: disk/profile, disk/tor_dir,
                    disk/downloads, disk/ntfs/<letter>

This module re-hashes every file those records name and compares. A mismatch, an unsafe
record (absolute path, "..", a symbolic link anywhere in the folder) means the folder is not
what was acquired, and the pipeline refuses to parse it (see main.run_pipeline). A file a
record names but that is not there, a file no record covers, or a folder with no records at
all is reported but does not block: those are incomplete copies or hand-built folders, not
altered bytes -- and the modules report missing inputs themselves.

Stdlib only, no Qt.
"""

from __future__ import annotations

import os
import re
import threading
from collections.abc import Iterable
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path, PureWindowsPath

from core.hashing import hash_file
from core.progress import report as report_progress

HASH_SUFFIX = ".sha256"
HASH_LIST_NAME = "hashes.sha256"
MANIFEST_NAME = "acquire_manifest.json"
_LINE_RE = re.compile(r"([0-9a-fA-F]{64}) [ *](.+)")
# Files that describe the evidence rather than being it; not expected to carry a hash.
_METADATA_SUFFIXES = (".custody.json",)
_METADATA_NAMES = frozenset({"custody.json"})

STATUS_VERIFIED = "verified"  # every hash record matched
STATUS_FAILED = "failed"  # a mismatch or an unsafe record: do not parse this evidence
STATUS_UNVERIFIED = "unverified"  # nothing to check against (no hash records at all)
STATUS_NOT_APPLICABLE = "not_applicable"  # no evidence folder and no hashed inputs


def _hash_workers() -> int:
    # hashlib releases the GIL, so threads hash files in parallel. TRANCE_WORKERS=1 keeps
    # everything sequential, same switch the rest of the pipeline honours.
    if os.environ.get("TRANCE_WORKERS", "").strip() == "1":
        return 1
    return min(4, os.cpu_count() or 1)


def _is_hash_record(path: Path) -> bool:
    return path.name.endswith(HASH_SUFFIX)


def _is_metadata(path: Path) -> bool:
    return path.name in _METADATA_NAMES or path.name.endswith(_METADATA_SUFFIXES)


def _unsafe_name(name: str) -> bool:
    relative = Path(name)
    return (
        relative.is_absolute()
        or bool(PureWindowsPath(name).drive)
        or name.startswith(("/", "\\"))
        or ".." in Path(name.replace("\\", "/")).parts
    )


def _walk(root: Path) -> tuple[list[Path], list[Path]]:
    """(regular files, symbolic links) under root, never following a link."""
    files: list[Path] = []
    links: list[Path] = []
    for current, dirnames, filenames in os.walk(root, followlinks=False):
        here = Path(current)
        for name in list(dirnames):
            if (here / name).is_symlink() or _is_junction(here / name):
                links.append(here / name)
                dirnames.remove(name)
        for name in filenames:
            path = here / name
            if path.is_symlink():
                links.append(path)
            elif path.is_file():
                files.append(path)
    return sorted(files), sorted(links)


def _is_junction(path: Path) -> bool:
    is_junction = getattr(os.path, "isjunction", None)  # Python 3.12+
    return bool(is_junction and is_junction(path))


def _parse_record(record: Path) -> tuple[list[tuple[str, str]], list[dict]]:
    """[(recorded digest, name relative to the record's folder)], [problems]."""
    entries: list[tuple[str, str]] = []
    problems: list[dict] = []
    try:
        text = record.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        return [], [{"record": str(record), "reason": f"unreadable hash record: {exc}"}]
    for number, line in enumerate(text.splitlines(), 1):
        if not line.strip():
            continue
        match = _LINE_RE.fullmatch(line.rstrip("\r"))
        if not match:
            problems.append(
                {"record": str(record), "line": number, "reason": "malformed SHA-256 line"}
            )
            continue
        digest, name = match.groups()
        if _unsafe_name(name):
            problems.append(
                {
                    "record": str(record),
                    "line": number,
                    "reason": f"path is not a safe relative path: {name!r}",
                }
            )
            continue
        entries.append((digest.lower(), name.replace("\\", "/")))
    if not entries and not problems:
        problems.append({"record": str(record), "reason": "empty hash record"})
    return entries, problems


def _display(path: Path, root: Path | None) -> str:
    if root is not None:
        try:
            return path.relative_to(root).as_posix()
        except ValueError:
            pass
    return str(path)


def verify_evidence(
    evidence_dir: Path | None, extra_inputs: Iterable[Path | str | None] = ()
) -> dict:
    """Verify every hash record in evidence_dir, plus the records next to any input that
    lives outside it (a file's <name>.sha256, a folder's hashes.sha256).

    Returns a JSON-serialisable summary; "status" is one of the STATUS_* values and only
    STATUS_FAILED should stop analysis.
    """
    root = Path(evidence_dir).resolve() if evidence_dir else None
    records: list[Path] = []
    covered_scope: list[Path] = []  # files whose coverage is checked (for "unhashed")
    links: list[Path] = []
    problems: list[dict] = []

    if root is not None:
        if not root.is_dir():
            return {
                "status": STATUS_FAILED,
                "evidence_dir": str(evidence_dir),
                "message": f"Evidence folder not found: {evidence_dir}",
                "checked": 0,
                "verified": [],
                "mismatched": [],
                "missing": [],
                "invalid": [],
                "unhashed": [],
            }
        files, links = _walk(root)
        records = [f for f in files if _is_hash_record(f)]
        covered_scope = [f for f in files if not _is_hash_record(f) and not _is_metadata(f)]

    for raw in extra_inputs:
        if not raw:
            continue
        path = Path(raw).resolve()
        if root is not None and path.is_relative_to(root):
            continue  # already covered by the folder walk
        if path.is_file():
            sidecar = path.with_name(path.name + HASH_SUFFIX)
            if sidecar.is_file():
                records.append(sidecar)
            covered_scope.append(path)
        elif path.is_dir():
            sub_files, sub_links = _walk(path)
            links += sub_links
            records += [f for f in sub_files if _is_hash_record(f)]
            covered_scope += [
                f for f in sub_files if not _is_hash_record(f) and not _is_metadata(f)
            ]

    # (target file, recorded digest, record it came from)
    expectations: list[tuple[Path, str, Path]] = []
    for record in dict.fromkeys(records):
        entries, record_problems = _parse_record(record)
        problems += record_problems
        for digest, name in entries:
            expectations.append((record.parent / name, digest, record))

    targets = sorted({target for target, _, _ in expectations if target.is_file()})
    counted = _ProgressCounter(sum(t.stat().st_size for t in targets))
    with ThreadPoolExecutor(max_workers=_hash_workers()) as pool:
        actual = dict(zip(targets, pool.map(lambda t: _safe_hash(t, counted.add), targets)))

    verified: list[str] = []
    mismatched: list[dict] = []
    missing: list[dict] = []
    for target, digest, record in expectations:
        shown = _display(target, root)
        if not target.is_file():
            missing.append({"path": shown, "record": _display(record, root)})
            continue
        got = actual.get(target)
        if isinstance(got, OSError):
            problems.append({"record": _display(record, root), "reason": f"{shown}: {got}"})
        elif got != digest:
            mismatched.append(
                {
                    "path": shown,
                    "record": _display(record, root),
                    "recorded": digest,
                    "actual": got,
                }
            )
        else:
            verified.append(shown)

    for link in links:
        problems.append(
            {
                "record": _display(link, root),
                "reason": "symbolic link or junction inside the evidence -- refusing to follow it",
            }
        )

    hashed_targets = {target.resolve() for target, _, _ in expectations}
    unhashed = sorted(
        {_display(f, root) for f in covered_scope if f.resolve() not in hashed_targets}
    )

    if mismatched or problems:
        status = STATUS_FAILED
    elif expectations:
        status = STATUS_VERIFIED
    elif root is not None:
        status = STATUS_UNVERIFIED
    else:
        status = STATUS_NOT_APPLICABLE

    return {
        "status": status,
        "evidence_dir": str(evidence_dir) if evidence_dir else None,
        "message": _message(status, verified, mismatched, missing, problems, unhashed),
        "checked": len(expectations),
        "verified": sorted(set(verified)),
        "mismatched": mismatched,
        "missing": missing,
        "invalid": problems,
        "unhashed": unhashed,
    }


def _safe_hash(path: Path, on_chunk=None) -> str | OSError:
    try:
        return hash_file(path, on_chunk=on_chunk)
    except OSError as exc:
        return exc


class _ProgressCounter:
    """Bytes hashed so far across the hashing threads; a progress line every 2%. A multi-GB
    memory image makes this check half a minute or more before any module starts."""

    def __init__(self, total: int):
        self.total, self.done, self.shown = max(total, 1), 0, -2
        self.lock = threading.Lock()

    def add(self, n: int) -> None:
        with self.lock:
            self.done += n
            done, percent = self.done, 100 * self.done // self.total
            if percent < self.shown + 2:
                return
            self.shown = percent
        report_progress(
            f"checking evidence hashes {percent}% ({done / 1e9:.1f} of {self.total / 1e9:.1f} GB)"
        )


def _message(status, verified, mismatched, missing, problems, unhashed) -> str:
    if status == STATUS_FAILED:
        parts = []
        if mismatched:
            names = ", ".join(m["path"] for m in mismatched[:5])
            more = f" (+{len(mismatched) - 5} more)" if len(mismatched) > 5 else ""
            parts.append(
                f"{len(mismatched)} file(s) do not match the hash recorded at acquisition: "
                f"{names}{more}"
            )
        if problems:
            parts.append(f"{len(problems)} unsafe or unreadable hash record(s)")
        return (
            "Evidence integrity check FAILED -- "
            + "; ".join(parts)
            + ". The evidence was changed or damaged after acquisition; it was not analysed."
        )
    if status == STATUS_VERIFIED:
        text = f"All {len(set(verified))} hashed evidence file(s) match their acquisition hashes."
    elif status == STATUS_UNVERIFIED:
        text = "No hash records found in the evidence folder, so nothing could be verified."
    else:
        text = "No evidence folder and no hash records next to the inputs; nothing verified."
    if missing:
        text += f" {len(missing)} file(s) listed in a hash record are missing from the copy."
    if unhashed:
        text += f" {len(unhashed)} file(s) are not covered by any hash record."
    return text


def evidence_inputs(module_kwargs: dict[str, dict]) -> list[Path]:
    """The input paths in main.run_pipeline's module_kwargs that carry acquisition hashes.
    A disk image or mounted volume is left out: it has no acquisition hash records, and
    hashing a whole disk up front would double the slowest part of the run."""
    keys = {
        "module_a_registry": ("ntuser", "system", "amcache", "software", "usrclass"),
        "module_b_disk": ("profile_dir", "tor_dir", "downloads_scan", "ntfs_dir"),
        "module_c_memory": ("dump",),
    }
    paths = []
    for module, names in keys.items():
        for name in names:
            value = (module_kwargs.get(module) or {}).get(name)
            if value:
                paths.append(Path(value))
    return paths
