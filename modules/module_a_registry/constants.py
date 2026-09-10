"""Tor-relevance filtering constants for Module A.

Per the Module A Description (2.3 Processing Pipeline / Filtering), the raw
output of each regipy plugin covers *every* program the artifact ever
recorded, not just Tor Browser. This module isolates the Tor-relevant subset
before normalization.

Design note — recall over precision: Module A's job is to surface
*candidates* for the correlation engine and the human examiner, not to make
a final determination. A missed Tor artifact (false negative) is worse than
an extra candidate that the examiner discards, so the filters below are
deliberately broad substring/basename matches rather than strict equality
or regex-anchored paths.
"""

from __future__ import annotations

# Artifact type labels shared across extraction, filtering, and
# normalization so no module has to hardcode string literals independently.
ARTIFACT_TYPE_USER_ASSIST = "UserAssist"
ARTIFACT_TYPE_SHIMCACHE = "ShimCache"
ARTIFACT_TYPE_AMCACHE = "Amcache"
ARTIFACT_TYPE_RECENTDOCS = "RecentDocs"

# Bare executable/basename matches. Kept deliberately short: only binaries
# that are unique to the Tor ecosystem belong here. Notably, "firefox.exe"
# is NOT listed — Tor Browser's firefox.exe is indistinguishable by name
# alone from a vanilla Firefox install, so it is only caught via the path
# markers below (Tor Browser always runs firefox.exe from a "Tor Browser"
# install directory). Bridge/pluggable-transport binaries, on the other
# hand, are Tor-specific enough by name alone to match safely.
TOR_EXECUTABLE_NAMES: frozenset[str] = frozenset(
    {
        "tor.exe",
        "tor.real",
        "start tor browser.exe",
        "start-tor-browser.exe",
        "start-tor-browser",
        "torbrowser.exe",
        "tor-browser.exe",
        "torlauncher.exe",
        "tor-gencert.exe",
        "obfs4proxy.exe",
        "obfs4proxy",
        "snowflake-client.exe",
        "snowflake-client",
        "meek-client.exe",
        "meek-client",
        "webtunnel-client.exe",
        "webtunnel-client",
    }
)

# Case-insensitive substring markers checked against a full path. Broader
# than the executable list on purpose: they catch install directories,
# profile directories, and downloaded artifacts even when the file at the
# end of the path isn't itself a known Tor binary (e.g. a log file, a
# shortcut, or a document dropped inside the Tor Browser folder).
TOR_PATH_MARKERS: tuple[str, ...] = (
    "tor browser",
    "tor-browser",
    "torbrowser",
    "\\browser\\torbrowser\\",
    "desktop\\tor browser",
    "\\tbb\\",
    "torproject",
    ".torproject.org",
    "\\appdata\\roaming\\tor\\",
    "\\appdata\\local\\tor browser\\",
)

# Where to look for a "path-like" string in each artifact type's raw regipy
# dict. Shared between the pipeline's filtering step and normalize.py's
# description-building step so both agree on what "the path" means for a
# given artifact type.
_CANDIDATE_PATH_FIELDS: dict[str, tuple[str, ...]] = {
    ARTIFACT_TYPE_USER_ASSIST: ("name",),
    ARTIFACT_TYPE_SHIMCACHE: ("path",),
    ARTIFACT_TYPE_AMCACHE: ("full_path", "lower_case_long_path", "path", "name"),
    ARTIFACT_TYPE_RECENTDOCS: ("name", "key_path"),
}


def candidate_path(artifact_type: str, entry: dict) -> str | None:
    """Best-effort extraction of the "path" a raw regipy entry describes.

    Different regipy plugins name their path-bearing field differently
    (UserAssist: "name", ShimCache: "path", Amcache: "full_path" or
    "lower_case_long_path" depending on hive schema version). This
    centralizes that lookup so it isn't duplicated between filtering and
    normalization.
    """
    for field in _CANDIDATE_PATH_FIELDS.get(artifact_type, ()):
        value = entry.get(field)
        if value:
            return value
    return None


def is_tor_related(path: str | None) -> bool:
    """Conservative Tor-relevance filter over a single path-like string.

    Returns True if `path` looks like it belongs to a Tor Browser install,
    profile, or bundled binary. Deliberately favors recall: an ambiguous
    path is not rejected just because it could theoretically belong to
    something else (see module docstring).
    """
    if not path:
        return False

    normalized = str(path).strip().lower().replace("/", "\\")

    if any(marker in normalized for marker in TOR_PATH_MARKERS):
        return True

    basename = normalized.rsplit("\\", 1)[-1]
    return basename in TOR_EXECUTABLE_NAMES
