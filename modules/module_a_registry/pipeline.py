"""Module A orchestration: ingest -> hash -> extract -> filter -> normalize -> verify -> output.

Implements the processing pipeline described in Module A Description 2.3:

  1. Ingest: hive paths are received strictly read-only (regipy never opens
     hives for writing; see extractors.py).
  2. Integrity check: each hive is SHA-256 hashed on ingest, *before* any
     parsing begins, and logged to the chain-of-custody record (2.3,
     2.4 "Read-only enforcement").
  3. Extraction: regipy plugins parse UserAssist, ShimCache, Amcache, and
     RecentDocs (extractors.py).
  4. Filtering: is_tor_related() isolates Tor-relevant entries from the
     full extracted set (constants.py).
  5. Normalization: filtered results become core.schema.Artifact objects
     with confidence baked into the description (normalize.py).
  6. A second hash of each hive is taken *after* parsing and compared
     against the ingest hash; any mismatch raises IntegrityError. This is
     the pipeline half of the "final integrity check" in 1.4 Forensic
     Soundness (the tool-exit-wide check is the caller's/report layer's
     responsibility across all modules).

All three hive paths are optional: per 2.3/2.4 ("Independent testability")
and the brief's instruction that Module A should report what it can even
if only some hives were acquired, a missing hive simply means the artifact
types that depend on it are skipped and noted in the summary rather than
the whole module failing.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path

from core.config import TranceConfig
from core.custody_log import CustodyEntry, CustodyLog
from core.exceptions import IntegrityError, ParsingError
from core.hashing import hash_file
from core.schema import Artifact

from .constants import (
    ARTIFACT_TYPE_AMCACHE,
    ARTIFACT_TYPE_BAM,
    ARTIFACT_TYPE_COMDLG32,
    ARTIFACT_TYPE_INSTALLEDPROGRAMS,
    ARTIFACT_TYPE_MUICACHE,
    ARTIFACT_TYPE_RECENTDOCS,
    ARTIFACT_TYPE_RUNMRU,
    ARTIFACT_TYPE_SHIMCACHE,
    ARTIFACT_TYPE_USER_ASSIST,
    ARTIFACT_TYPE_WORDWHEELQUERY,
    candidate_path,
    is_tor_installer,
    is_tor_related,
)
from .extractors import (
    extract_amcache,
    extract_bam,
    extract_comdlg32,
    extract_installed_programs,
    extract_muicache,
    extract_profiles,
    extract_recentdocs,
    extract_runmru,
    extract_shimcache,
    extract_user_assist,
    extract_word_wheel_query,
)
from .normalize import MODULE_NAME, normalize_entry

# (artifact_type, extractor_fn) pairs keyed by which physical hive they read
# from. NTUSER.DAT feeds two artifact types (UserAssist, RecentDocs); each
# hive is still only hashed once (see _process_hive) even though multiple
# plugins run against it.
#
# These are built by functions rather than as module-level tuples so that
# each lookup of e.g. `extract_user_assist` happens at call time against
# this module's current global namespace — which is what lets tests patch
# `modules.module_a_registry.pipeline.extract_user_assist` and have the
# pipeline actually pick up the replacement. A module-level tuple built at
# import time would instead freeze in the original function object.
_ExtractorSpec = tuple[str, Callable[[Path], list[dict]]]


def _ntuser_extractors() -> tuple[_ExtractorSpec, ...]:
    return (
        (ARTIFACT_TYPE_USER_ASSIST, extract_user_assist),
        (ARTIFACT_TYPE_RECENTDOCS, extract_recentdocs),
        (ARTIFACT_TYPE_MUICACHE, extract_muicache),
        (ARTIFACT_TYPE_RUNMRU, extract_runmru),
        (ARTIFACT_TYPE_WORDWHEELQUERY, extract_word_wheel_query),
        (ARTIFACT_TYPE_COMDLG32, extract_comdlg32),
    )


def _system_extractors() -> tuple[_ExtractorSpec, ...]:
    return (
        (ARTIFACT_TYPE_SHIMCACHE, extract_shimcache),
        (ARTIFACT_TYPE_BAM, extract_bam),
    )


def _amcache_extractors() -> tuple[_ExtractorSpec, ...]:
    return ((ARTIFACT_TYPE_AMCACHE, extract_amcache),)


def _software_extractors() -> tuple[_ExtractorSpec, ...]:
    return ((ARTIFACT_TYPE_INSTALLEDPROGRAMS, extract_installed_programs),)


@dataclass
class ModuleAResult:
    findings: list[Artifact]
    summary: str
    errors: list[str] = field(default_factory=list)
    custody_log_path: str | None = None
    # ProfileList (SID -> username/profile-path) -- reference data, not a Tor-relevance
    # finding, so it never goes through findings/Artifact; kept separately for the
    # report's own small profiles table and for narrative.py's SID resolution.
    profiles: list[dict] = field(default_factory=list)


def _process_hive(
    hive_label: str,
    hive_path: Path | None,
    extractor_specs: tuple[_ExtractorSpec, ...],
    custody_log: CustodyLog,
    findings: list[Artifact],
    errors: list[str],
    stats: dict,
) -> None:
    if hive_path is None:
        return

    hive_path = Path(hive_path)

    pre_hash = hash_file(hive_path)
    custody_log.record(
        CustodyEntry(
            artifact_path=str(hive_path),
            sha256=pre_hash,
            action="ingest_pre_parse",
            notes=hive_label,
        )
    )

    for artifact_type, extractor_fn in extractor_specs:
        try:
            raw_entries = extractor_fn(hive_path)
        except ParsingError as exc:
            errors.append(f"{artifact_type} ({hive_label}): {exc}")
            continue

        for entry in raw_entries:
            path = candidate_path(artifact_type, entry)
            if not is_tor_related(path):
                continue

            artifact = normalize_entry(artifact_type, entry, str(hive_path))
            findings.append(artifact)
            _update_stats(stats, artifact_type, entry, artifact.timestamp, path)

    post_hash = hash_file(hive_path)
    custody_log.record(
        CustodyEntry(
            artifact_path=str(hive_path),
            sha256=post_hash,
            action="post_parse_verify",
            notes=hive_label,
        )
    )

    if post_hash != pre_hash:
        raise IntegrityError(
            f"Hash mismatch for {hive_label} at {hive_path}: "
            f"ingest={pre_hash} post-parse={post_hash}. "
            "Source evidence was modified during parsing — this must never happen "
            "under strictly read-only extraction."
        )


def _process_profiles(
    software_path: Path | None,
    custody_log: CustodyLog,
    errors: list[str],
) -> list[dict]:
    """ProfileList is reference data (SID -> username/profile-path), not a Tor-relevance
    finding -- extracted separately from _process_hive's filter-and-normalize pipeline,
    with its own pre/post integrity hashing over the same SOFTWARE hive (read twice --
    once here, once by _software_extractors() -- negligible cost against a cheap SHA-256
    over a registry-hive-sized file, and keeps _process_hive's contract unchanged rather
    than growing it a non-filtered side channel)."""
    if software_path is None:
        return []

    software_path = Path(software_path)
    pre_hash = hash_file(software_path)
    custody_log.record(
        CustodyEntry(
            artifact_path=str(software_path),
            sha256=pre_hash,
            action="ingest_pre_parse",
            notes="SOFTWARE (ProfileList)",
        )
    )

    try:
        profiles = extract_profiles(software_path)
    except ParsingError as exc:
        errors.append(f"ProfileList (SOFTWARE): {exc}")
        profiles = []

    post_hash = hash_file(software_path)
    custody_log.record(
        CustodyEntry(
            artifact_path=str(software_path),
            sha256=post_hash,
            action="post_parse_verify",
            notes="SOFTWARE (ProfileList)",
        )
    )
    if post_hash != pre_hash:
        raise IntegrityError(
            f"Hash mismatch for SOFTWARE (ProfileList) at {software_path}: "
            f"ingest={pre_hash} post-parse={post_hash}. "
            "Source evidence was modified during parsing — this must never happen "
            "under strictly read-only extraction."
        )
    return profiles


def _update_stats(
    stats: dict,
    artifact_type: str,
    entry: dict,
    clean_timestamp: str | None,
    path: str | None,
) -> None:
    """Accumulate the numbers _build_summary() needs.

    `clean_timestamp` is the already-normalized Artifact.timestamp for this same entry
    (epoch-zero FILETIME already stripped to None by normalize.py) -- using it here instead
    of re-reading the raw entry keeps that cleanup a single source of truth, and fixes a
    second latent instance of the same "fake 1601 date" bug for Amcache's install_timestamp.

    UserAssist's run_counter is a *cumulative* count Windows keeps per component (per
    path/GUID), paired with a *single* timestamp it overwrites on every run -- it never
    retains when any run before the most recent one happened. So "how many times was
    Tor Browser launched" has to come from run_counter itself, not from counting distinct
    timestamps (that undercounts to 1 the moment the same component is launched twice,
    since only the latest timestamp survives). Two things still need guarding against:
    regipy duplicating the same raw entry (must not double-count -- keyed by path, so a
    repeat with the same value is just an overwrite) and a shortcut + the program it
    starts moving together as one logical "Tor Browser" (each keeps its own path key, so
    the final count is the max across all of them, not a sum). The installer itself is
    excluded -- running the installer isn't "launching Tor Browser".
    """
    if artifact_type == ARTIFACT_TYPE_AMCACHE:
        ts = clean_timestamp
        if ts and (stats["install_timestamp"] is None or ts < stats["install_timestamp"]):
            stats["install_timestamp"] = ts
    elif artifact_type == ARTIFACT_TYPE_USER_ASSIST:
        run_counter = entry.get("run_counter") or 0
        if run_counter and path and not is_tor_installer(path):
            existing = stats["userassist_run_counts"].get(path, 0)
            stats["userassist_run_counts"][path] = max(existing, run_counter)
        if clean_timestamp and (
            stats["last_executed"] is None or clean_timestamp > stats["last_executed"]
        ):
            stats["last_executed"] = clean_timestamp
    elif artifact_type == ARTIFACT_TYPE_BAM:
        # BAM carries no run-count, only a last-execution timestamp -- it can extend
        # last_executed (an independent subsystem corroborating "still running this
        # recently") but never affects the launch-count number itself.
        if clean_timestamp and (
            stats["last_executed"] is None or clean_timestamp > stats["last_executed"]
        ):
            stats["last_executed"] = clean_timestamp


def _format_summary_timestamp(value: str | None) -> str | None:
    """Same human-readable intent as report.py's template-side timestamp formatting,
    but done here with stdlib only: this summary sentence also reaches plain stdout and
    module_a_registry.json, not just the HTML report, so it can't depend on a Jinja
    filter that only exists inside report.py's Environment."""
    if not value:
        return value
    try:
        dt = datetime.fromisoformat(value)
    except ValueError:
        return value
    return dt.strftime("%Y-%m-%d %H:%M:%S") + " UTC"


def _build_summary(
    findings: list[Artifact],
    errors: list[str],
    hives_provided: dict[str, bool],
    stats: dict,
) -> str:
    parts = []
    if stats["install_timestamp"]:
        parts.append(
            f"Tor Browser installed {_format_summary_timestamp(stats['install_timestamp'])}"
        )
    launch_count = max(stats["userassist_run_counts"].values(), default=0)
    if launch_count:
        parts.append(f"launched {launch_count} time{'s' if launch_count != 1 else ''}")
    if stats["last_executed"]:
        parts.append(f"last run {_format_summary_timestamp(stats['last_executed'])}")

    if parts:
        summary = ", ".join(parts) + "."
    elif findings:
        summary = (
            f"{len(findings)} Tor-related registry artifact(s) found, but no install/run "
            "timeline could be established from UserAssist/Amcache/BAM."
        )
    else:
        summary = "No Tor Browser artifacts found in the provided hives."

    missing = [
        label
        for label, provided in (
            ("NTUSER.DAT", hives_provided["ntuser"]),
            ("SYSTEM", hives_provided["system"]),
            ("Amcache.hve", hives_provided["amcache"]),
            ("SOFTWARE", hives_provided["software"]),
        )
        if not provided
    ]
    if missing:
        summary += f" (Not analyzed — hive(s) not provided: {', '.join(missing)}.)"
    if errors:
        summary += f" ({len(errors)} extraction error(s) encountered.)"

    return summary


def run_module_a(
    config: TranceConfig,
    ntuser: Path | None = None,
    system: Path | None = None,
    amcache: Path | None = None,
    software: Path | None = None,
) -> ModuleAResult:
    """Run Module A against whichever hives were acquired.

    All four arguments are optional so Module A can run — and be
    evaluated — independently of what Modules B/C need, and so it degrades
    gracefully when only a subset of hives were acquired (2.3/2.4).
    """
    output_dir = Path(config.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    custody_log = CustodyLog(output_dir / "module_a_custody_log.json")
    findings: list[Artifact] = []
    errors: list[str] = []
    stats = {"install_timestamp": None, "userassist_run_counts": {}, "last_executed": None}
    hives_provided = {
        "ntuser": ntuser is not None,
        "system": system is not None,
        "amcache": amcache is not None,
        "software": software is not None,
    }

    _process_hive("NTUSER.DAT", ntuser, _ntuser_extractors(), custody_log, findings, errors, stats)
    _process_hive("SYSTEM", system, _system_extractors(), custody_log, findings, errors, stats)
    _process_hive(
        "Amcache.hve", amcache, _amcache_extractors(), custody_log, findings, errors, stats
    )
    _process_hive(
        "SOFTWARE", software, _software_extractors(), custody_log, findings, errors, stats
    )
    profiles = _process_profiles(software, custody_log, errors)

    custody_log.save()

    summary = _build_summary(findings, errors, hives_provided, stats)
    return ModuleAResult(
        findings=findings,
        summary=summary,
        errors=errors,
        profiles=profiles,
        custody_log_path=str(custody_log.log_path),
    )


def write_output(result: ModuleAResult, output_path: Path) -> Path:
    """Write module_a_registry.json in the shared module-output format.

    Deliberately contains no run timestamp: the PDF's repeatability
    requirement ("byte-identical findings excluding a separately logged
    run timestamp") is satisfied by keeping this file timestamp-free
    entirely — run-specific timestamps live only in the chain-of-custody
    log (core.custody_log.CustodyEntry), which is intentionally a
    separate file.
    """
    output_path = Path(output_path)
    payload = {
        "module": MODULE_NAME,
        "findings": [asdict(f) for f in result.findings],
        "summary": result.summary,
        "profiles": result.profiles,
    }
    output_path.write_text(json.dumps(payload, indent=2))
    return output_path
