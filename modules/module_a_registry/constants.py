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

import re
from collections.abc import Iterable

# Artifact type labels shared across extraction, filtering, and
# normalization so no module has to hardcode string literals independently.
ARTIFACT_TYPE_USER_ASSIST = "UserAssist"
ARTIFACT_TYPE_SHIMCACHE = "ShimCache"
ARTIFACT_TYPE_AMCACHE = "Amcache"
ARTIFACT_TYPE_RECENTDOCS = "RecentDocs"
ARTIFACT_TYPE_BAM = "BAM"
ARTIFACT_TYPE_MUICACHE = "MUICache"
ARTIFACT_TYPE_RUNMRU = "RunMRU"
ARTIFACT_TYPE_WORDWHEELQUERY = "WordWheelQuery"
ARTIFACT_TYPE_COMDLG32 = "ComDlg32"
ARTIFACT_TYPE_INSTALLEDPROGRAMS = "InstalledPrograms"

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
    ARTIFACT_TYPE_BAM: ("executable",),
    ARTIFACT_TYPE_MUICACHE: ("path",),
    ARTIFACT_TYPE_RUNMRU: ("command",),
    ARTIFACT_TYPE_WORDWHEELQUERY: ("name",),
    ARTIFACT_TYPE_COMDLG32: ("path",),
    ARTIFACT_TYPE_INSTALLEDPROGRAMS: ("DisplayName", "InstallLocation", "service_name"),
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


# Tor Browser's own installer filename shape, recognized literally rather than guessed
# from a generic "looks like an installer" heuristic. Shared by pipeline.py (running the
# installer isn't "launching Tor Browser" -- excluded from launch-count stats) and
# narrative.py (describing the download/install in plain English) so both agree on what
# counts as the installer without duplicating the pattern.
_TOR_INSTALLER_RE = re.compile(
    r"tor-browser-windows-(?P<arch>x86_64|i686|arm64)-(?P<portable>portable-)?"
    r"(?P<version>\d+(?:\.\d+)+)\.exe$",
    re.IGNORECASE,
)


def parse_tor_installer_filename(path: str | None) -> dict | None:
    """Returns {"version", "arch", "portable"} for a Tor Browser installer filename,
    or None if `path` doesn't match that shape."""
    if not path:
        return None
    basename = str(path).replace("/", "\\").rsplit("\\", 1)[-1]
    match = _TOR_INSTALLER_RE.match(basename)
    if not match:
        return None
    return {
        "version": match.group("version"),
        "arch": match.group("arch"),
        "portable": bool(match.group("portable")),
    }


def is_tor_installer(path: str | None) -> bool:
    return parse_tor_installer_filename(path) is not None


# ---------------------------------------------------------------------------
# \Device\HarddiskVolumeN -> drive letter (best-effort, same-evidence inference)
# ---------------------------------------------------------------------------
#
# Amcache/BAM sometimes record a path using Windows' internal volume name
# (e.g. "\Device\HarddiskVolume6\Tor Browser\...") instead of a drive letter.
# That ordinal is assigned by the mount manager at boot and is NOT persisted
# anywhere in the registry in a directly-queryable form -- regipy's own
# MountedDevicesPlugin (SYSTEM\MountedDevices) maps a drive letter to a volume
# GUID or a disk-signature+partition-offset pair, never to a HarddiskVolumeN
# ordinal, so it cannot answer this specific question and is deliberately not
# used here. The one reliable signal available is the evidence itself: if
# another record names the SAME file using a plain drive letter (e.g.
# UserAssist's "E:\Tor Browser\Browser\firefox.exe" next to BAM's
# "\Device\HarddiskVolume6\Tor Browser\Browser\firefox.exe"), the two are
# almost certainly two OS-level names for one file, and the match is reported
# as an inference, never a direct read.
_HARDDISK_VOLUME_RE = re.compile(r"\\device\\harddiskvolume(\d+)\\(.*)$", re.IGNORECASE)
_DRIVE_LETTER_PATH_RE = re.compile(r"^([A-Za-z]):\\(.*)$")


def harddiskvolume_number(path: str | None) -> str | None:
    """The N in a "\\Device\\HarddiskVolumeN\\..." path, or None if path isn't one."""
    if not path:
        return None
    match = _HARDDISK_VOLUME_RE.search(path)
    return match.group(1) if match else None


def infer_drive_letters(paths: Iterable[str]) -> dict[str, str]:
    """Best-effort: for every "\\Device\\HarddiskVolumeN\\<suffix>" path in `paths`,
    look for a "<letter>:\\<suffix>" path (same suffix, case-insensitive) also present
    in `paths`. Returns {harddiskvolume_path: letter} only for an UNAMBIGUOUS match --
    a suffix matched by zero or more than one drive letter is left unresolved rather
    than guessed. Deterministic and order-independent (set-based)."""
    letters_by_suffix: dict[str, set[str]] = {}
    for path in paths:
        match = _DRIVE_LETTER_PATH_RE.match(path)
        if match:
            letters_by_suffix.setdefault(match.group(2).lower(), set()).add(match.group(1).upper())

    resolved: dict[str, str] = {}
    for path in paths:
        match = _HARDDISK_VOLUME_RE.search(path)
        if not match:
            continue
        letters = letters_by_suffix.get(match.group(2).lower())
        if letters and len(letters) == 1:
            resolved[path] = next(iter(letters))
    return resolved
