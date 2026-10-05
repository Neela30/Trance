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
)

MODULE_NAME = "module_a_registry"

# Windows FILETIME's epoch is 1601-01-01 -- a raw FILETIME value of 0 (field never set)
# converts to exactly that date, which regipy hands back as an ordinary-looking
# timestamp. Left alone, "no timestamp recorded" displays as a real-looking date 425
# years in the past; this catches that sentinel and turns it back into None, regardless
# of which artifact type or sub-second precision produced it.
_NULL_FILETIME_DATE = "1601-01-01"


def _clean_timestamp(timestamp: str | None) -> str | None:
    if timestamp and timestamp.startswith(_NULL_FILETIME_DATE):
        return None
    return timestamp


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


def _normalize_bam(entry: dict) -> tuple[str, str | None]:
    path = candidate_path(ARTIFACT_TYPE_BAM, entry) or "<unknown>"
    sid = entry.get("sid")
    sid_suffix = f", sid={sid}" if sid else ""
    description = (
        f"BAM (Background Activity Moderator) last-execution evidence for '{path}'"
        f"{sid_suffix}. Confidence: HIGH — an independent OS subsystem's own "
        "last-run record, separate from UserAssist/ShimCache/Amcache."
    )
    return description, entry.get("timestamp")


def _normalize_muicache(entry: dict) -> tuple[str, str | None]:
    path = candidate_path(ARTIFACT_TYPE_MUICACHE, entry) or "<unknown>"
    display_name = entry.get("display_name")
    name_suffix = f", display_name={display_name!r}" if display_name else ""
    description = (
        f"MUICache entry for '{path}'{name_suffix}. "
        "Confidence: MEDIUM — shows the app was invoked via the shell at some point, "
        "not confirmed execution."
    )
    return description, entry.get("last_write")


def _normalize_runmru(entry: dict) -> tuple[str, str | None]:
    # "for '...'" wording is required here, not just stylistic -- report.py's
    # _PATH_RE (shared by every artifact type) only matches "for '...'"/"entry '...'",
    # and without a match this entry would silently drop out of the cross-hive
    # component correlation table entirely.
    command = candidate_path(ARTIFACT_TYPE_RUNMRU, entry) or "<unknown>"
    description = (
        f"RunMRU evidence for '{command}' (command typed into the Run dialog). "
        "Confidence: LOW — contextual/corroborating evidence only, "
        "not direct Tor Browser execution evidence."
    )
    return description, entry.get("last_write")


def _normalize_word_wheel_query(entry: dict) -> tuple[str, str | None]:
    # See _normalize_runmru's comment -- "for '...'" wording is load-bearing for
    # report.py's _PATH_RE, not just stylistic.
    query = candidate_path(ARTIFACT_TYPE_WORDWHEELQUERY, entry) or "<unknown>"
    description = (
        f"WordWheelQuery evidence for '{query}' (search typed into Explorer/Start "
        "search). Confidence: LOW — contextual/corroborating evidence only, "
        "not direct Tor Browser execution evidence."
    )
    return description, entry.get("last_write")


def _normalize_comdlg32(entry: dict) -> tuple[str, str | None]:
    path = candidate_path(ARTIFACT_TYPE_COMDLG32, entry) or "<unknown>"
    mru_type = entry.get("mru_type")
    type_suffix = f" ({mru_type})" if mru_type else ""
    description = (
        f"ComDlg32 entry for '{path}'{type_suffix} — used in a file Open/Save dialog. "
        "Confidence: LOW — contextual/corroborating evidence only, "
        "not direct Tor Browser execution evidence; regipy's own PIDL parsing here is "
        "best-effort and can be noisy."
    )
    return description, entry.get("last_write")


def _normalize_installed_programs(entry: dict) -> tuple[str, str | None]:
    path = candidate_path(ARTIFACT_TYPE_INSTALLEDPROGRAMS, entry) or "<unknown>"
    publisher = entry.get("Publisher")
    publisher_suffix = f", publisher={publisher!r}" if publisher else ""
    # InstallDate (when present) is the Uninstall key's own raw "YYYYMMDD" string, not
    # ISO-8601 -- kept in the description as context rather than as Artifact.timestamp
    # (which every other type here treats as a parseable ISO timestamp). The key's own
    # last-write time (already ISO, via regipy's convert_wintime) is the real timestamp.
    install_date = entry.get("InstallDate")
    date_suffix = f", InstallDate={install_date}" if install_date else ""
    description = (
        f"Installed-programs (Uninstall key) entry for '{path}'{publisher_suffix}"
        f"{date_suffix}. Confidence: HIGH — a registered install, largely independent "
        "of execution and shutdown state (though a portable Tor Browser won't register "
        "here)."
    )
    return description, entry.get("timestamp")


_NORMALIZERS = {
    ARTIFACT_TYPE_USER_ASSIST: _normalize_user_assist,
    ARTIFACT_TYPE_SHIMCACHE: _normalize_shimcache,
    ARTIFACT_TYPE_AMCACHE: _normalize_amcache,
    ARTIFACT_TYPE_RECENTDOCS: _normalize_recentdocs,
    ARTIFACT_TYPE_BAM: _normalize_bam,
    ARTIFACT_TYPE_MUICACHE: _normalize_muicache,
    ARTIFACT_TYPE_RUNMRU: _normalize_runmru,
    ARTIFACT_TYPE_WORDWHEELQUERY: _normalize_word_wheel_query,
    ARTIFACT_TYPE_COMDLG32: _normalize_comdlg32,
    ARTIFACT_TYPE_INSTALLEDPROGRAMS: _normalize_installed_programs,
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
    timestamp = _clean_timestamp(timestamp)

    return Artifact(
        module=MODULE_NAME,
        artifact_type=artifact_type,
        source=str(source_hive),
        description=description,
        sha256=None,
        timestamp=timestamp,
    )
