"""Evidence verification and disposable working copies for disk analysis."""

from __future__ import annotations

import re
import shutil
import tempfile
from contextlib import contextmanager
from pathlib import Path, PureWindowsPath

from core.exceptions import IntegrityError
from core.hashing import hash_file


def inventory(root: Path) -> dict[str, str]:
    """Hash regular files without following links out of the evidence tree."""
    result = {}
    for path in sorted(root.rglob("*")):
        if path.is_symlink():
            raise IntegrityError(f"Evidence contains a symbolic link: {path.relative_to(root)}")
        if path.is_file():
            result[path.relative_to(root).as_posix()] = hash_file(path)
        elif not path.is_dir():
            raise IntegrityError(f"Evidence contains a non-regular file: {path}")
    return result


def verify_hashes(evidence_dir: Path) -> dict:
    """Verify sha256sum relative paths, including nested files and binary markers."""
    root = evidence_dir.resolve()
    manifest = root / "hashes.sha256"
    if manifest.is_symlink():
        raise IntegrityError("Hash manifest must not be a symbolic link")
    if not manifest.exists():
        return {}
    result = {}
    for number, line in enumerate(manifest.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        match = re.fullmatch(r"([0-9a-fA-F]{64}) [ *](.+)", line)
        if not match:
            result[f"line:{number}"] = {"status": "invalid", "reason": "Malformed SHA-256 entry"}
            continue
        digest, name = match.groups()
        relative = Path(name)
        if (
            relative.is_absolute()
            or PureWindowsPath(name).drive
            or ".." in relative.parts
            or "\\" in name
        ):
            result[f"line:{number}"] = {
                "status": "invalid",
                "reason": "Expected a safe relative path",
            }
            continue
        key = relative.as_posix()
        target = root / relative
        if key in result or key in (".", "hashes.sha256"):
            result[f"line:{number}"] = {
                "status": "invalid",
                "reason": "Duplicate or self-referencing entry",
            }
            continue
        if any(
            p.is_symlink()
            for p in [target, *target.parents]
            if p != root and p.is_relative_to(root)
        ):
            result[key] = {"status": "invalid", "reason": "Symbolic link in manifest path"}
        elif not target.is_file():
            result[key] = {"status": "missing"}
        else:
            actual = hash_file(target)
            result[key] = {
                "status": "match" if actual == digest.lower() else "MISMATCH",
                "recorded": digest.lower(),
                "actual": actual,
            }
    if not result:
        result["manifest"] = {"status": "invalid", "reason": "Empty hash manifest"}
    return result


@contextmanager
def working_copy(evidence_dir: Path):
    """Check the manifest and copy bytes before opening any evidence databases.

    Input must be a static acquisition, not a live browser profile. Hashes record
    content integrity; they do not authenticate who originally acquired evidence.
    """
    root = evidence_dir.resolve(strict=True)
    before = inventory(root)
    verification = verify_hashes(root)
    failures = {k: v for k, v in verification.items() if v["status"] != "match"}
    if failures:
        raise IntegrityError(f"Manifest verification failed: {failures}")
    with tempfile.TemporaryDirectory(prefix="trance-profile-") as directory:
        copy = Path(directory) / "profile"
        shutil.copytree(root, copy, symlinks=True)
        if inventory(copy) != before or inventory(root) != before:
            raise IntegrityError("Evidence changed while creating the working copy")
        try:
            yield copy, before, verification
        finally:
            if inventory(root) != before:
                raise IntegrityError("Source evidence changed during analysis")


def external_output(path: Path, evidence_dir: Path) -> Path:
    resolved = path.resolve()
    if resolved.is_relative_to(evidence_dir.resolve()):
        raise ValueError("Reports and custody logs must be outside the evidence directory")
    if path.exists() or path.is_symlink():
        raise ValueError(f"Output already exists; choose a new path: {path}")
    return resolved
