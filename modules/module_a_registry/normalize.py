"""Converts each artifact type's raw regipy dict into the shared Artifact schema.

Per Module A Description 2.4 ("Confidence annotation"): ShimCache reflects
insertion order, not confirmed execution, and that caveat must be encoded
directly in the output schema, not left to report prose alone. Since
core.schema.Artifact has no dedicated confidence field, the confidence
level and its justification are baked directly into `description` for
every artifact type here — so it survives untouched through JSON
serialization and into the final report regardless of what the report
template chooses to render.

Confidence levels assigned (per 2.2 / 2.4 of the project brief):
  - UserAssist : HIGH  — GUI-launched execution evidence.
  - Amcache    : HIGH  — persists largely independent of execution/shutdown.
  - ShimCache  : MEDIUM — insertion-order evidence only, not confirmed execution.
  - RecentDocs : LOW   — contextual/corroborating evidence only.
"""

from __future__ import annotations

from core.schema import Artifact

from .constants import (
    ARTIFACT_TYPE_AMCACHE,
    ARTIFACT_TYPE_RECENTDOCS,
    ARTIFACT_TYPE_SHIMCACHE,
    ARTIFACT_TYPE_USER_ASSIST,
    candidate_path,
)

MODULE_NAME = "module_a_registry"


def _first(entry: dict, keys: tuple[str, ...]) -> object | None:
    for key in keys:
        value = entry.get(key)
        if value:
            return value
    return None


def _normalize_user_assist(entry: dict) -> tuple[str, str | None]:
    path = candidate_path(ARTIFACT_TYPE_USER_ASSIST, entry) or "<unknown>"
    details = [f"run_count={entry.get('run_counter')}"]
    if entry.get("focus_count") is not None:
        details.append(f"focus_count={entry.get('focus_count')}")
    if entry.get("total_focus_time_ms") is not None:
        details.append(f"total_focus_time_ms={entry.get('total_focus_time_ms')}")
    description = (
        f"UserAssist evidence for '{path}' ({', '.join(details)}). "
        "Confidence: HIGH — GUI-launched execution evidence recorded by Windows Explorer."
    )
    return description, entry.get("timestamp")


def _normalize_shimcache(entry: dict) -> tuple[str, str | None]:
    path = candidate_path(ARTIFACT_TYPE_SHIMCACHE, entry) or "<unknown>"
    timestamp = _first(entry, ("last_mod_date", "last_mod_time", "exec_time", "last_update"))
    description = (
        f"ShimCache/AppCompatCache entry for '{path}'. "
        "Confidence: MEDIUM — insertion-order evidence only, not confirmed execution."
    )
    return description, timestamp


def _normalize_amcache(entry: dict) -> tuple[str, str | None]:
    path = candidate_path(ARTIFACT_TYPE_AMCACHE, entry) or "<unknown>"
    details = []
    sha1 = entry.get("sha1")
    if sha1:
        details.append(f"sha1={sha1}")
    size = entry.get("size", entry.get("file_size"))
    if size is not None:
        details.append(f"size={size}")
    detail_suffix = f" ({', '.join(details)})" if details else ""
    description = (
        f"Amcache install/first-seen evidence for '{path}'{detail_suffix}. "
        "Confidence: HIGH — persists largely independent of execution and shutdown state."
    )
    timestamp = entry.get("timestamp") or entry.get("created_timestamp")
    return description, timestamp


def _normalize_recentdocs(entry: dict) -> tuple[str, str | None]:
    name = candidate_path(ARTIFACT_TYPE_RECENTDOCS, entry) or "<unknown>"
    extension = entry.get("extension")
    ext_suffix = f", extension={extension}" if extension else ""
    description = (
        f"RecentDocs entry '{name}'{ext_suffix} — recently accessed file. "
        "Confidence: LOW — contextual/corroborating evidence only, "
        "not direct Tor Browser execution evidence."
    )
    return description, entry.get("last_write")


_NORMALIZERS = {
    ARTIFACT_TYPE_USER_ASSIST: _normalize_user_assist,
    ARTIFACT_TYPE_SHIMCACHE: _normalize_shimcache,
    ARTIFACT_TYPE_AMCACHE: _normalize_amcache,
    ARTIFACT_TYPE_RECENTDOCS: _normalize_recentdocs,
}


def normalize_entry(artifact_type: str, entry: dict, source_hive: str) -> Artifact:
    """Convert one raw regipy entry into the shared core.schema.Artifact shape.

    `source_hive` is the path (or label) of the hive the entry came from —
    it is recorded verbatim in Artifact.source for traceability back to the
    acquired evidence file, independent of the chain-of-custody log.
    """
    try:
        normalizer = _NORMALIZERS[artifact_type]
    except KeyError as exc:
        raise ValueError(f"Unknown artifact_type: {artifact_type!r}") from exc

    description, timestamp = normalizer(entry)

    return Artifact(
        module=MODULE_NAME,
        artifact_type=artifact_type,
        source=str(source_hive),
        description=description,
        sha256=None,
        timestamp=timestamp,
    )
