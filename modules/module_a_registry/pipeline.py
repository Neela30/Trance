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
from pathlib import Path

from core.config import TranceConfig
from core.custody_log import CustodyEntry, CustodyLog
from core.exceptions import IntegrityError, ParsingError
from core.hashing import hash_file
from core.schema import Artifact

from .constants import (
    ARTIFACT_TYPE_AMCACHE,
    ARTIFACT_TYPE_RECENTDOCS,
    ARTIFACT_TYPE_SHIMCACHE,
    ARTIFACT_TYPE_USER_ASSIST,
    candidate_path,
    is_tor_related,
)
from .extractors import (
    extract_amcache,
    extract_recentdocs,
    extract_shimcache,
    extract_user_assist,
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
    )


def _system_extractors() -> tuple[_ExtractorSpec, ...]:
    return ((ARTIFACT_TYPE_SHIMCACHE, extract_shimcache),)


def _amcache_extractors() -> tuple[_ExtractorSpec, ...]:
    return ((ARTIFACT_TYPE_AMCACHE, extract_amcache),)


@dataclass
class ModuleAResult:
    findings: list[Artifact]
    summary: str
    errors: list[str] = field(default_factory=list)
    custody_log_path: str | None = None


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

            findings.append(normalize_entry(artifact_type, entry, str(hive_path)))
            _update_stats(stats, artifact_type, entry)

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


def _update_stats(stats: dict, artifact_type: str, entry: dict) -> None:
    """Accumulate the raw numbers _build_summary() needs, from the raw entry.

    Done here (against the raw regipy dict) rather than by re-parsing the
    rendered description string later, so summary numbers never depend on
    description text formatting.
    """
    if artifact_type == ARTIFACT_TYPE_AMCACHE:
        ts = entry.get("timestamp") or entry.get("created_timestamp")
        if ts and (stats["install_timestamp"] is None or ts < stats["install_timestamp"]):
            stats["install_timestamp"] = ts
    elif artifact_type == ARTIFACT_TYPE_USER_ASSIST:
        stats["run_count_total"] += entry.get("run_counter") or 0
        ts = entry.get("timestamp")
        if ts and (stats["last_executed"] is None or ts > stats["last_executed"]):
            stats["last_executed"] = ts


def _build_summary(
    findings: list[Artifact],
    errors: list[str],
    hives_provided: dict[str, bool],
    stats: dict,
) -> str:
    parts = []
    if stats["install_timestamp"]:
        parts.append(f"Tor Browser installed {stats['install_timestamp']}")
    if stats["run_count_total"]:
        parts.append(f"executed {stats['run_count_total']} times")
    if stats["last_executed"]:
        parts.append(f"last run {stats['last_executed']}")

    if parts:
        summary = ", ".join(parts) + "."
    elif findings:
        summary = (
            f"{len(findings)} Tor-related registry artifact(s) found, but no install/run "
            "timeline could be established from UserAssist/Amcache."
        )
    else:
        summary = "No Tor Browser artifacts found in the provided hives."

    missing = [
        label
        for label, provided in (
            ("NTUSER.DAT", hives_provided["ntuser"]),
            ("SYSTEM", hives_provided["system"]),
            ("Amcache.hve", hives_provided["amcache"]),
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
) -> ModuleAResult:
    """Run Module A against whichever hives were acquired.

    All three arguments are optional so Module A can run — and be
    evaluated — independently of what Modules B/C need, and so it degrades
    gracefully when only a subset of hives were acquired (2.3/2.4).
    """
    output_dir = Path(config.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    custody_log = CustodyLog(output_dir / "module_a_custody_log.json")
    findings: list[Artifact] = []
    errors: list[str] = []
    stats = {"install_timestamp": None, "run_count_total": 0, "last_executed": None}
    hives_provided = {
        "ntuser": ntuser is not None,
        "system": system is not None,
        "amcache": amcache is not None,
    }

    _process_hive("NTUSER.DAT", ntuser, _ntuser_extractors(), custody_log, findings, errors, stats)
    _process_hive("SYSTEM", system, _system_extractors(), custody_log, findings, errors, stats)
    _process_hive(
        "Amcache.hve", amcache, _amcache_extractors(), custody_log, findings, errors, stats
    )

    custody_log.save()

    summary = _build_summary(findings, errors, hives_provided, stats)
    return ModuleAResult(
        findings=findings,
        summary=summary,
        errors=errors,
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
    }
    output_path.write_text(json.dumps(payload, indent=2))
    return output_path
