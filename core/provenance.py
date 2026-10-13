"""Where a case's findings came from: tool, runtime, acquisition, and every evidence input.

A court (or an independent examiner repeating the work) needs to know which version of
TRANCE produced the report, on what machine and software, from which files, and whether
those files are byte-for-byte what was acquired. build_provenance() gathers that into
findings.json["provenance"], which the report prints as "Analysis provenance" and
"Evidence examined".

Each evidence file is checked against the hash recorded when it was acquired: a
`<file>.sha256` sidecar (registry hives, memory images) or the `hashes.sha256` manifest of
its folder (profile, tor_dir, downloads scan, NTFS export). A file a module has already
hashed this run is not read a second time: Module C's memory-image hash, Module B's raw
image hash and its own manifest checks of the profile, tor folder and NTFS export are
reused. Everything else is hashed here (registry hives and small files only).

Statuses per item:
    verified     hash now == hash recorded at acquisition
    MISMATCH     the file changed since acquisition -- the report flags it
    unrecorded   no acquisition-time hash exists to compare against (hash still listed)
    missing      the input path does not exist
    not_hashed   a mounted volume (a directory tree, not a file)
"""

from __future__ import annotations

import getpass
import json
import platform
import re
import socket
import subprocess
import sys
from datetime import datetime, timezone
from importlib import metadata
from pathlib import Path

from core.hashing import hash_file
from core.schema import ModuleResult
from core.version import __version__

REPO_ROOT = Path(__file__).resolve().parent.parent
MANIFEST_FILENAME = "acquire_manifest.json"
FOLDER_MANIFEST = "hashes.sha256"

# Distribution names whose version can change what TRANCE reports.
LIBRARIES = ("regipy", "jinja2", "lz4", "psutil", "tzlocal", "tzdata", "volatility3", "PySide6")

# (module, kwarg) -> plain-English label, in report order.
FILE_INPUTS = (
    ("module_a_registry", "system", "SYSTEM registry hive"),
    ("module_a_registry", "software", "SOFTWARE registry hive"),
    ("module_a_registry", "ntuser", "NTUSER.DAT registry hive"),
    ("module_a_registry", "usrclass", "UsrClass.dat registry hive"),
    ("module_a_registry", "amcache", "Amcache.hve"),
    ("module_c_memory", "dump", "Memory image"),
    ("module_b_disk", "downloads_scan", "Live downloads scan"),
    ("module_b_disk", "disk_image", "Disk image"),
)
FOLDER_INPUTS = (
    ("module_b_disk", "profile_dir", "Tor Browser profile", "profile"),
    ("module_b_disk", "tor_dir", "Tor daemon data folder", "tor_daemon"),
)

_SHA256_LINE = re.compile(r"([0-9a-fA-F]{64}) [ *](.+)")


def tool_info() -> dict:
    commit, dirty = _git_state()
    return {
        "name": "TRANCE",
        "version": __version__,
        "git_commit": commit,
        "git_dirty": dirty,
        "packaged": bool(getattr(sys, "frozen", False)),
    }


def _git_state() -> tuple[str | None, bool | None]:
    """The source checkout's commit and whether tracked files differ from it. None for a
    packaged exe or a copy without git: the version number is then the only identifier."""
    if getattr(sys, "frozen", False) or not (REPO_ROOT / ".git").exists():
        return None, None
    try:
        commit = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=REPO_ROOT,
            capture_output=True,
            text=True,
            timeout=10,
            check=True,
        ).stdout.strip()
        changed = subprocess.run(
            ["git", "status", "--porcelain", "--untracked-files=no"],
            cwd=REPO_ROOT,
            capture_output=True,
            text=True,
            timeout=30,
            check=True,
        ).stdout.strip()
    except (OSError, subprocess.SubprocessError):
        return None, None
    return commit or None, bool(changed)


def runtime_info() -> dict:
    try:
        user = getpass.getuser()
    except Exception:  # no login name in some containers/services
        user = None
    return {
        "python": platform.python_version(),
        "platform": platform.platform(),
        "hostname": socket.gethostname(),
        "user": user,
        "libraries": {name: _library_version(name) for name in LIBRARIES},
    }


def _library_version(name: str) -> str | None:
    try:
        return metadata.version(name)
    except metadata.PackageNotFoundError:
        return None


def acquisition_info(evidence_dir: Path | None) -> dict | None:
    """What acquire_all.py recorded about the capture, if the evidence folder has its
    manifest. Only the facts about the acquisition itself -- per-file paths are covered by
    the evidence items."""
    if not evidence_dir:
        return None
    path = Path(evidence_dir) / MANIFEST_FILENAME
    if not path.is_file():
        return None
    try:
        manifest = json.loads(path.read_text())
    except (OSError, ValueError):
        return {"manifest": str(path), "error": "acquire_manifest.json could not be read"}
    memory = manifest.get("memory", {}).get("full_image", {})
    custody_logs = [
        section.get("custody_log_path")
        for section in (
            manifest.get("registry", {}),
            manifest.get("disk", {}),
            manifest.get("disk", {}).get("ntfs", {}),
        )
        if isinstance(section, dict) and section.get("custody_log_path")
    ]
    return {
        "manifest": str(path),
        "manifest_sha256": hash_file(path),
        "acquired_at": manifest.get("acquired_at"),
        # Written by acquire_all.py since this field was added; absent in older captures.
        "acquired_by": manifest.get("acquired_by"),
        "acquisition_order": manifest.get("acquisition_order"),
        "winpmem_path": memory.get("winpmem_path"),
        "winpmem_sha256": memory.get("winpmem_sha256"),
        "custody_logs": custody_logs,
    }


def _sidecar_hash(path: Path) -> str | None:
    """The acquisition-time hash for one file: its `<name>.sha256` sidecar, else its
    folder's hashes.sha256 entry for it."""
    sidecar = path.with_name(path.name + ".sha256")
    if sidecar.is_file():
        first = sidecar.read_text(errors="replace").split()
        if first and re.fullmatch(r"[0-9a-fA-F]{64}", first[0]):
            return first[0].lower()
    manifest = path.parent / FOLDER_MANIFEST
    if manifest.is_file():
        for line in manifest.read_text(errors="replace").splitlines():
            match = _SHA256_LINE.fullmatch(line.strip())
            if match and match.group(2) == path.name:
                return match.group(1).lower()
    return None


def _status(actual: str | None, recorded: str | None) -> str:
    if recorded is None:
        return "unrecorded"
    return "verified" if actual == recorded else "MISMATCH"


def _file_item(label: str, module: str, path: Path, known_sha256: str | None) -> dict:
    item = {"label": label, "module": module, "path": str(path), "kind": "file"}
    if not path.is_file():
        return {**item, "status": "missing", "size_bytes": None, "sha256": None}
    actual = known_sha256 or hash_file(path)
    recorded = _sidecar_hash(path)
    return {
        **item,
        "size_bytes": path.stat().st_size,
        "sha256": actual,
        "acquisition_sha256": recorded,
        "hashed_by": "module" if known_sha256 else "provenance",
        "status": _status(actual, recorded),
    }


def _items_from_verification(label: str, folder: Path, verification: dict) -> list[dict]:
    """One item per file listed in a folder's hashes.sha256, from evidence.verify_hashes()'s
    result shape ({relative: {"status": "match"|"MISMATCH"|"missing"|"invalid", ...}})."""
    items = []
    for relative, entry in sorted(verification.items()):
        state = entry.get("status")
        path = folder / relative
        items.append(
            {
                "label": label,
                "module": "module_b_disk",
                "path": str(path),
                "kind": "file",
                "size_bytes": path.stat().st_size if path.is_file() else None,
                "sha256": entry.get("actual"),
                "acquisition_sha256": entry.get("recorded"),
                "hashed_by": "module",
                "status": {"match": "verified", "MISMATCH": "MISMATCH", "missing": "missing"}.get(
                    state, "unrecorded"
                ),
                **({"note": entry["reason"]} if entry.get("reason") else {}),
            }
        )
    return items


def _folder_items(label: str, folder: Path, verification: dict | None) -> list[dict]:
    if not folder.is_dir():
        return [
            {
                "label": label,
                "module": "module_b_disk",
                "path": str(folder),
                "kind": "folder",
                "status": "missing",
                "size_bytes": None,
                "sha256": None,
            }
        ]
    if verification:
        return _items_from_verification(label, folder, verification)
    # The module didn't get as far as its own check (or the folder has no manifest):
    # hash what is there so the exhibit list is still complete.
    if (folder / FOLDER_MANIFEST).is_file():
        from modules.module_b_disk.evidence import verify_hashes

        return _items_from_verification(label, folder, verify_hashes(folder))
    return [
        _file_item(label, "module_b_disk", p, None)
        for p in sorted(folder.rglob("*"))
        if p.is_file()
    ]


def _known_hash(
    module: str, kwarg: str, path: Path, results: dict[str, ModuleResult]
) -> str | None:
    """A hash a module already computed for this exact file this run (large files only)."""
    result = results.get(module)
    if result is None:
        return None
    if kwarg == "dump":
        dump = result.details.get("dump") or {}
        if dump.get("sha256") and _same_path(dump.get("path"), path):
            return dump["sha256"]
    if kwarg == "disk_image":
        carve = result.details.get("raw_carve") or {}
        if carve.get("image_sha256") and _same_path(carve.get("image"), path):
            return carve["image_sha256"]
    return None


def _same_path(recorded: str | None, path: Path) -> bool:
    if not recorded:
        return False
    try:
        return Path(recorded).resolve() == path.resolve()
    except OSError:
        return False


def evidence_items(module_kwargs: dict[str, dict], results: list[ModuleResult]) -> list[dict]:
    by_module = {r.module: r for r in results}
    items: list[dict] = []
    for module, kwarg, label in FILE_INPUTS:
        value = module_kwargs.get(module, {}).get(kwarg)
        if value:
            path = Path(value)
            items.append(
                _file_item(label, module, path, _known_hash(module, kwarg, path, by_module))
            )

    disk = by_module.get("module_b_disk")
    disk_details = disk.details if disk else {}
    disk_kwargs = module_kwargs.get("module_b_disk", {})
    for _module, kwarg, label, section in FOLDER_INPUTS:
        value = disk_kwargs.get(kwarg)
        if value:
            verification = (disk_details.get(section) or {}).get("hash_verification")
            items.extend(_folder_items(label, Path(value), verification))

    ntfs_dir = disk_kwargs.get("ntfs_dir")
    # disk_root wins over the export when both are given (Module B ignores the export then).
    if ntfs_dir and not disk_kwargs.get("disk_root") and Path(ntfs_dir).is_dir():
        from modules.module_b_disk.analyze_ntfs_journal import exported_volumes

        verified = disk_details.get("ntfs_export_verification") or {}
        for drive, volume in sorted(exported_volumes(Path(ntfs_dir)).items()):
            label = f"NTFS metadata export ({drive}:)"
            items.extend(_folder_items(label, volume, verified.get(drive)))

    disk_root = disk_kwargs.get("disk_root")
    if disk_root:
        items.append(
            {
                "label": "Mounted disk volume (read-only)",
                "module": "module_b_disk",
                "path": str(disk_root),
                "kind": "volume",
                "status": "not_hashed",
                "size_bytes": None,
                "sha256": None,
                "note": "a mounted directory tree, not a file: hash the disk image it was "
                "mounted from to identify it",
            }
        )
    return items


def build_provenance(
    module_kwargs: dict[str, dict],
    results: list[ModuleResult],
    evidence_dir: Path | None,
    started_at: str,
) -> dict:
    items = evidence_items(module_kwargs, results)
    counts: dict[str, int] = {}
    for item in items:
        counts[item["status"]] = counts.get(item["status"], 0) + 1
    return {
        "tool": tool_info(),
        "runtime": runtime_info(),
        "analysis_started_at": started_at,
        "analysis_finished_at": datetime.now(timezone.utc).isoformat(),
        "acquisition": acquisition_info(evidence_dir),
        "evidence_items": items,
        "evidence_summary": counts,
    }
