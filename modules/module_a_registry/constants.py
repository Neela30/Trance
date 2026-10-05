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

# "Context" artifact types (see CATEGORY_CONTEXT below) -- machine-wide facts that never
# go through is_tor_related() at all, unlike the ten types above.
ARTIFACT_TYPE_COMPUTERNAME = "ComputerName"
ARTIFACT_TYPE_TIMEZONE = "TimeZone"
ARTIFACT_TYPE_WINDOWSVERSION = "WindowsVersion"

# Phase 1 of the Module A roadmap -- execution evidence. All six are CATEGORY_TOR_DIRECT
# (filtered by is_tor_related()/is_tor_related_entry() same as the original ten). MUICache
# from UsrClass.dat deliberately reuses ARTIFACT_TYPE_MUICACHE above rather than getting
# its own constant -- same kind of evidence as the NTUSER-sourced MUICache, just from
# Windows Vista+'s actual location for it; merging them into one report section (sources
# differentiated by Artifact.source) is more useful than an artificial split.
ARTIFACT_TYPE_SHELLBAGS = "ShellBags"
ARTIFACT_TYPE_COMPAT_ASSISTANT_STORE = "CompatAssistantStore"
ARTIFACT_TYPE_FIREFOX_LAUNCHER = "FirefoxLauncher"
ARTIFACT_TYPE_APP_SWITCHED = "AppSwitched"
ARTIFACT_TYPE_TYPEDPATHS = "TypedPaths"
ARTIFACT_TYPE_LASTVISITEDPIDLMRU = "LastVisitedPidlMRU"

# Phase 2 of the Module A roadmap -- device evidence. All six are CATEGORY_CONTEXT (see
# below): none of them have anything Tor-specific in their own content (a USB stick's
# manufacturer string doesn't say "Tor Browser"), so is_tor_related() would never
# usefully match them -- they're only interesting *alongside* a tor-direct finding, same
# treatment as the three Phase 0 context facts above. report.py's device correlation
# (_build_device_correlation()) additionally flags whichever of these specifically
# matches the Tor install's drive letter, rather than relying on category alone to
# separate "the Tor drive" from "every USB device this machine has ever seen".
ARTIFACT_TYPE_USBSTOR = "USBStor"
ARTIFACT_TYPE_USBDEVICES = "USBDevices"
ARTIFACT_TYPE_MOUNTEDDEVICES = "MountedDevices"
ARTIFACT_TYPE_MOUNTPOINTS2 = "MountPoints2"
ARTIFACT_TYPE_EMDMGMT = "EMDMgmt"
ARTIFACT_TYPE_PORTABLEDEVICES = "PortableDevices"

# Phase 3 of the Module A roadmap -- network context. Both CATEGORY_CONTEXT (see below):
# a network's own name/MAC/lease data never says "Tor" by itself, same reasoning as Phase
# 2's device-evidence types -- only interesting *alongside* a tor-direct finding.
ARTIFACT_TYPE_NETWORK_PROFILE = "NetworkProfile"
ARTIFACT_TYPE_NETWORK_INTERFACE = "NetworkInterface"

# Phase 4 of the Module A roadmap -- persistence and configuration. All three are
# CATEGORY_TOR_DIRECT (filtered by is_tor_related_entry(), same as the original ten) --
# unlike Phase 2/3's device/network context types, these ARE Tor evidence in their own
# right once they reference Tor at all (a scheduled autostart or a configured proxy is a
# deliberate, Tor-specific configuration choice, not a generic machine fact); an entry
# that doesn't reference Tor is simply never kept (see is_tor_related_entry() below and
# pipeline.py's module docstring) -- Module A never reports "every autostart entry".
ARTIFACT_TYPE_RUNKEY = "RunKey"
ARTIFACT_TYPE_SERVICE = "Service"
ARTIFACT_TYPE_PROXY_SETTINGS = "ProxySettings"

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
    ARTIFACT_TYPE_SHELLBAGS: ("path",),
    ARTIFACT_TYPE_COMPAT_ASSISTANT_STORE: ("path",),
    ARTIFACT_TYPE_FIREFOX_LAUNCHER: ("path",),
    ARTIFACT_TYPE_APP_SWITCHED: ("path",),
    ARTIFACT_TYPE_TYPEDPATHS: ("path",),
    ARTIFACT_TYPE_LASTVISITEDPIDLMRU: ("path",),
    # RunKey/Service match on "executable" -- the command/ImagePath value with any quoting
    # and arguments already stripped (see extract_command_executable() below), not the raw
    # "command"/"image_path" field. is_tor_related()'s basename check needs a bare
    # executable path to match "tor.exe" at all; a raw value like
    # '"C:\\Tor\\tor.exe" --service' would never match otherwise (confirmed against a real
    # SYSTEM hive -- see this module's "Command-line executable extraction" section).
    ARTIFACT_TYPE_RUNKEY: ("executable",),
    ARTIFACT_TYPE_SERVICE: ("executable",),
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


# A handful of artifact types carry Tor-relevance in a field OTHER than (or in addition
# to) candidate_path()'s "the path" -- e.g. LastVisitedPidlMRU's "program" field (the
# invoking exe's full path) can establish Tor-relevance even when the paired folder path
# alone gives no hint at all (a Tor Browser Save-As dialog pointed at a perfectly generic
# Downloads folder). Only types that need this get an entry; every other type's
# is_tor_related_entry() call is exactly equivalent to the plain
# is_tor_related(candidate_path(...)) check it replaces.
_ADDITIONAL_TOR_CHECK_FIELDS: dict[str, tuple[str, ...]] = {
    ARTIFACT_TYPE_LASTVISITEDPIDLMRU: ("program",),
}


# ---------------------------------------------------------------------------
# Command-line executable extraction (Phase 4 of the Module A roadmap).
# ---------------------------------------------------------------------------
#
# Run/RunOnce values and a service's ImagePath are full command lines, not bare paths --
# e.g. '"C:\Tor\tor.exe" --service' or '%SystemRoot%\System32\svchost.exe -k Group' --
# confirmed against a real SYSTEM hive (RtkAudUService's real ImagePath has exactly this
# quoted-path-plus-arguments shape). is_tor_related()'s basename check
# (normalized.rsplit("\\", 1)[-1]) assumes the whole string IS the path, so on a raw
# command line it would extract 'tor.exe" --service' instead of 'tor.exe' and never match
# TOR_EXECUTABLE_NAMES at all -- a real, confirmed gap, not a hypothetical one. This
# mimics Windows' own CreateProcess command-line parsing just enough to isolate the
# executable: a leading quote runs to the next quote; otherwise the token runs to the
# first space.
def extract_command_executable(command: str | None) -> str | None:
    if not command:
        return None
    stripped = command.strip()
    if stripped.startswith('"'):
        end = stripped.find('"', 1)
        return stripped[1:end] if end != -1 else stripped[1:]
    return stripped.split(" ", 1)[0]


# A Tor Expert Bundle service is very often literally named "tor" (or a close variant)
# regardless of what its ImagePath looks like (e.g. nssm-wrapped, where the image is
# nssm.exe, not tor.exe) -- checked as a second, independent signal alongside the
# executable-path check in is_tor_related_entry() below, since neither alone is reliable
# for every real-world install shape.
_SERVICE_NAME_TOR_MARKERS = frozenset({"tor", "tor service", "tor windows service"})


def is_tor_service_name(name: str | None) -> bool:
    return bool(name) and name.strip().lower() in _SERVICE_NAME_TOR_MARKERS


# ---------------------------------------------------------------------------
# Tor SOCKS proxy configuration (Phase 4 of the Module A roadmap).
# ---------------------------------------------------------------------------
#
# "Is this proxy configuration Tor-related" isn't a path-substring question like every
# other artifact type here -- it's "enabled AND pointing at Tor's own SOCKS port", so it
# gets its own predicate rather than a candidate_path()/is_tor_related() entry. Per the
# project brief: only claim "other programs were set to route traffic through Tor" when
# BOTH conditions hold -- a disabled proxy, or one pointing elsewhere, is not Tor evidence
# (and per pipeline.py's filtering, no ProxySettings finding is produced at all for either
# case -- Module A doesn't report "every" proxy configuration, same as RunKey/Service).
TOR_SOCKS_PORTS = frozenset({"9050", "9150"})
_TOR_PROXY_HOSTS = frozenset({"127.0.0.1", "localhost"})


def _proxy_server_has_tor_socks_port(proxy_server: str | None) -> bool:
    """ProxyServer can be a single "host:port" (all protocols) or a multi-protocol string
    like "ftp=1.2.3.4:21;http=1.2.3.4:80;socks=127.0.0.1:9050" -- Windows' own documented
    shape for per-protocol proxies. Checks every ';'-separated segment (stripping a
    leading "protocol=" if present) rather than assuming the single-proxy shape, since a
    SOCKS-only Tor proxy is commonly configured as just one segment among several."""
    if not proxy_server:
        return False
    segments = proxy_server.split(";") if ";" in proxy_server else [proxy_server]
    for segment in segments:
        segment = segment.strip()
        if "=" in segment:
            _, _, segment = segment.partition("=")
        host, _, port = segment.strip().rpartition(":")
        if host and host.lower() in _TOR_PROXY_HOSTS and port in TOR_SOCKS_PORTS:
            return True
    return False


def is_tor_proxy_config(entry: dict) -> bool:
    if entry.get("proxy_enable") != 1:
        return False
    return _proxy_server_has_tor_socks_port(entry.get("proxy_server"))


def is_tor_related_entry(artifact_type: str, entry: dict) -> bool:
    """Like is_tor_related(candidate_path(artifact_type, entry)), but ORs in any
    additional type-specific fields from _ADDITIONAL_TOR_CHECK_FIELDS -- see that dict's
    docstring. This is what pipeline.py's _process_hive() calls for the keep/discard
    filtering decision; candidate_path() itself is unchanged and still used on its own
    wherever only the single "display" path is needed (e.g. _update_stats()).

    Two Phase 4 artifact types need a predicate other than the generic path check:
    ProxySettings (is_tor_proxy_config() -- "enabled AND pointing at a Tor SOCKS port" is
    not a path-substring question) and Service (also true if the service's own name is a
    literal Tor marker, independent of what its ImagePath looks like -- see
    is_tor_service_name())."""
    if artifact_type == ARTIFACT_TYPE_PROXY_SETTINGS:
        return is_tor_proxy_config(entry)
    if artifact_type == ARTIFACT_TYPE_SERVICE and is_tor_service_name(entry.get("name")):
        return True
    if is_tor_related(candidate_path(artifact_type, entry)):
        return True
    for field in _ADDITIONAL_TOR_CHECK_FIELDS.get(artifact_type, ()):
        if is_tor_related(entry.get(field)):
            return True
    return False


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


# ---------------------------------------------------------------------------
# Confidence / category -- single source of truth (Phase 0 of the Module A roadmap).
# ---------------------------------------------------------------------------
#
# Previously, confidence was a sentence baked into normalize.py's description prose for
# each type, AND independently restated as report.py's own CONFIDENCE_BY_TYPE map -- two
# places that had to be kept in sync by hand. Both now read from here instead; see
# normalize.py's normalize_entry() for how this is applied uniformly per artifact_type,
# and report.py's build_context() for how a section's displayed confidence is now read
# straight off a finding rather than from a second map.
#
# category distinguishes "matched is_tor_related(), this IS Tor evidence" (the ten types
# above) from "machine-wide context fact, never filtered by is_tor_related() at all" (the
# three below) -- see pipeline.py's run_module_a() for the rule that context findings are
# only kept in the final output when at least one tor-direct finding also exists in the
# same run (a computer name / time zone / Windows version is not interesting on its own).

CONFIDENCE_HIGH = "high"
CONFIDENCE_MEDIUM = "medium"
CONFIDENCE_LOW = "low"

CATEGORY_TOR_DIRECT = "tor-direct"
CATEGORY_CONTEXT = "context"

# Per Module A Description 2.4 / 2.2 -- same levels normalize.py has always assigned,
# just now data instead of ten near-identical docstring paragraphs:
#   HIGH   -- UserAssist/Amcache/BAM/InstalledPrograms: GUI-launch, install/first-seen,
#             independent last-run record, or registered install -- all largely
#             independent of execution/shutdown state once recorded.
#   MEDIUM -- ShimCache/MUICache: presence/insertion evidence, not confirmed execution.
#   LOW    -- RecentDocs/RunMRU/WordWheelQuery/ComDlg32: contextual/corroborating only.
# Context facts are all direct, authoritative single-value reads of the OS's own record
# (not execution evidence of anything) -- HIGH here means "this is what the OS says",
# not "this proves Tor ran".
ARTIFACT_CONFIDENCE: dict[str, str] = {
    ARTIFACT_TYPE_USER_ASSIST: CONFIDENCE_HIGH,
    ARTIFACT_TYPE_AMCACHE: CONFIDENCE_HIGH,
    ARTIFACT_TYPE_BAM: CONFIDENCE_HIGH,
    ARTIFACT_TYPE_INSTALLEDPROGRAMS: CONFIDENCE_HIGH,
    ARTIFACT_TYPE_SHIMCACHE: CONFIDENCE_MEDIUM,
    ARTIFACT_TYPE_MUICACHE: CONFIDENCE_MEDIUM,
    ARTIFACT_TYPE_RECENTDOCS: CONFIDENCE_LOW,
    ARTIFACT_TYPE_RUNMRU: CONFIDENCE_LOW,
    ARTIFACT_TYPE_WORDWHEELQUERY: CONFIDENCE_LOW,
    ARTIFACT_TYPE_COMDLG32: CONFIDENCE_LOW,
    ARTIFACT_TYPE_COMPUTERNAME: CONFIDENCE_HIGH,
    ARTIFACT_TYPE_TIMEZONE: CONFIDENCE_HIGH,
    ARTIFACT_TYPE_WINDOWSVERSION: CONFIDENCE_HIGH,
    ARTIFACT_TYPE_SHELLBAGS: CONFIDENCE_MEDIUM,
    ARTIFACT_TYPE_COMPAT_ASSISTANT_STORE: CONFIDENCE_HIGH,
    ARTIFACT_TYPE_FIREFOX_LAUNCHER: CONFIDENCE_HIGH,
    ARTIFACT_TYPE_APP_SWITCHED: CONFIDENCE_LOW,
    ARTIFACT_TYPE_TYPEDPATHS: CONFIDENCE_LOW,
    ARTIFACT_TYPE_LASTVISITEDPIDLMRU: CONFIDENCE_MEDIUM,
    ARTIFACT_TYPE_USBSTOR: CONFIDENCE_HIGH,
    ARTIFACT_TYPE_USBDEVICES: CONFIDENCE_MEDIUM,
    ARTIFACT_TYPE_MOUNTEDDEVICES: CONFIDENCE_HIGH,
    ARTIFACT_TYPE_MOUNTPOINTS2: CONFIDENCE_LOW,
    ARTIFACT_TYPE_EMDMGMT: CONFIDENCE_MEDIUM,
    ARTIFACT_TYPE_PORTABLEDEVICES: CONFIDENCE_LOW,
    # Phase 3 -- direct, authoritative OS records (same tier as USBSTOR/MountedDevices):
    # HIGH means "this is what the OS says", not "this proves Tor ran" (these are
    # CATEGORY_CONTEXT, never Tor evidence by themselves -- see ARTIFACT_CATEGORY below).
    ARTIFACT_TYPE_NETWORK_PROFILE: CONFIDENCE_HIGH,
    ARTIFACT_TYPE_NETWORK_INTERFACE: CONFIDENCE_HIGH,
    # Phase 4 -- a direct, authoritative read of what's configured (HIGH), but evidence of
    # CONFIGURATION, not of a specific run -- see each reason string below and the
    # project brief ("a Tor service/Run entry is evidence of configuration, not of a
    # specific run"). Only ever present at all when it already references Tor (see
    # is_tor_related_entry()'s ARTIFACT_TYPE_SERVICE/ARTIFACT_TYPE_PROXY_SETTINGS
    # special cases) -- CATEGORY_TOR_DIRECT, unlike Phase 2/3's context types.
    ARTIFACT_TYPE_RUNKEY: CONFIDENCE_HIGH,
    ARTIFACT_TYPE_SERVICE: CONFIDENCE_HIGH,
    ARTIFACT_TYPE_PROXY_SETTINGS: CONFIDENCE_HIGH,
}

# The exact justification wording normalize.py used to append to `description` as
# "Confidence: <LEVEL> — <reason>." -- moved here verbatim, nothing reworded, so this is a
# relocation, not a second interpretation.
ARTIFACT_CONFIDENCE_REASON: dict[str, str] = {
    ARTIFACT_TYPE_USER_ASSIST: "GUI-launched execution evidence recorded by Windows Explorer.",
    ARTIFACT_TYPE_AMCACHE: "persists largely independent of execution and shutdown state.",
    ARTIFACT_TYPE_BAM: (
        "an independent OS subsystem's own last-run record, separate from "
        "UserAssist/ShimCache/Amcache."
    ),
    ARTIFACT_TYPE_INSTALLEDPROGRAMS: (
        "a registered install, largely independent of execution and shutdown state "
        "(though a portable Tor Browser won't register here)."
    ),
    ARTIFACT_TYPE_SHIMCACHE: "insertion-order evidence only, not confirmed execution.",
    ARTIFACT_TYPE_MUICACHE: (
        "shows the app was invoked via the shell at some point, not confirmed execution."
    ),
    ARTIFACT_TYPE_RECENTDOCS: (
        "contextual/corroborating evidence only, not direct Tor Browser execution evidence."
    ),
    ARTIFACT_TYPE_RUNMRU: (
        "contextual/corroborating evidence only, not direct Tor Browser execution evidence."
    ),
    ARTIFACT_TYPE_WORDWHEELQUERY: (
        "contextual/corroborating evidence only, not direct Tor Browser execution evidence."
    ),
    ARTIFACT_TYPE_COMDLG32: (
        "contextual/corroborating evidence only, not direct Tor Browser execution evidence; "
        "regipy's own PIDL parsing here is best-effort and can be noisy."
    ),
    ARTIFACT_TYPE_COMPUTERNAME: (
        "read directly from one of the SYSTEM hive's ControlSets, the OS's own "
        "authoritative record."
    ),
    ARTIFACT_TYPE_TIMEZONE: (
        "read directly from one of the SYSTEM hive's ControlSets, the OS's own "
        "authoritative record."
    ),
    ARTIFACT_TYPE_WINDOWSVERSION: (
        "read directly from SOFTWARE's CurrentVersion key, the OS's own authoritative record."
    ),
    ARTIFACT_TYPE_SHELLBAGS: (
        "shows a folder was browsed in Explorer at some point, not confirmed program " "execution."
    ),
    ARTIFACT_TYPE_COMPAT_ASSISTANT_STORE: (
        "Windows' own Program Compatibility Assistant record of evaluating this specific "
        "executable path -- an independent OS subsystem, separate from "
        "UserAssist/ShimCache/Amcache/BAM."
    ),
    ARTIFACT_TYPE_FIREFOX_LAUNCHER: (
        "a Firefox-family browser's own self-reported record of its full executable path "
        "at launch."
    ),
    ARTIFACT_TYPE_APP_SWITCHED: (
        "shows the window was switched to via Alt+Tab/the taskbar at some point -- "
        "contextual/corroborating only, not direct Tor Browser execution evidence."
    ),
    ARTIFACT_TYPE_TYPEDPATHS: (
        "a path manually typed into Explorer's address bar -- contextual/corroborating "
        "evidence only, not direct Tor Browser execution evidence."
    ),
    ARTIFACT_TYPE_LASTVISITEDPIDLMRU: (
        "ties a specific program's full path to a folder it last browsed via a common "
        "dialog -- stronger than a bare Open/Save entry alone, still not confirmed "
        "execution."
    ),
    ARTIFACT_TYPE_USBSTOR: (
        "authoritative OS record of USB mass-storage connection history, an independent "
        "subsystem from UserAssist/ShimCache/Amcache."
    ),
    ARTIFACT_TYPE_USBDEVICES: (
        "shows a USB device was enumerated by Windows, not specific to mass-storage or "
        "drive-letter correlation."
    ),
    ARTIFACT_TYPE_MOUNTEDDEVICES: (
        "a direct, unambiguous OS record of a drive-letter-to-device mapping."
    ),
    ARTIFACT_TYPE_MOUNTPOINTS2: (
        "a per-user record that this volume was mounted at some point -- contextual only, "
        "same tier as TypedPaths."
    ),
    ARTIFACT_TYPE_EMDMGMT: (
        "an independent OS subsystem (ReadyBoost-eligibility testing) corroborating "
        "device presence, not execution evidence."
    ),
    ARTIFACT_TYPE_PORTABLEDEVICES: (
        "MTP/portable-device connection history -- tangential to a mass-storage Tor "
        "install, contextual only."
    ),
    ARTIFACT_TYPE_NETWORK_PROFILE: (
        "a direct OS record of a network connection, but the registry only keeps the "
        "first/last connection time per network, not a connection history."
    ),
    ARTIFACT_TYPE_NETWORK_INTERFACE: (
        "a direct OS record of this interface's IP/DHCP configuration at last update, "
        "not a log of every address this interface has ever held."
    ),
    ARTIFACT_TYPE_RUNKEY: (
        "evidence of configuration (set to start automatically), not evidence of any "
        "specific run."
    ),
    ARTIFACT_TYPE_SERVICE: (
        "evidence of configuration (installed as a Windows service), not evidence of any "
        "specific run."
    ),
    ARTIFACT_TYPE_PROXY_SETTINGS: (
        "a direct read of the configured proxy; evidence that other programs were set up "
        "to route through Tor, not evidence that they did."
    ),
}

# Only context types need an entry -- everything else defaults to CATEGORY_TOR_DIRECT via
# ARTIFACT_CATEGORY.get(artifact_type, CATEGORY_TOR_DIRECT), used by both pipeline.py (to
# decide whether an artifact_type's entries go through is_tor_related() filtering at all)
# and normalize.py (to set Artifact.category).
ARTIFACT_CATEGORY: dict[str, str] = {
    ARTIFACT_TYPE_COMPUTERNAME: CATEGORY_CONTEXT,
    ARTIFACT_TYPE_TIMEZONE: CATEGORY_CONTEXT,
    ARTIFACT_TYPE_WINDOWSVERSION: CATEGORY_CONTEXT,
    ARTIFACT_TYPE_USBSTOR: CATEGORY_CONTEXT,
    ARTIFACT_TYPE_USBDEVICES: CATEGORY_CONTEXT,
    ARTIFACT_TYPE_MOUNTEDDEVICES: CATEGORY_CONTEXT,
    ARTIFACT_TYPE_MOUNTPOINTS2: CATEGORY_CONTEXT,
    ARTIFACT_TYPE_EMDMGMT: CATEGORY_CONTEXT,
    ARTIFACT_TYPE_PORTABLEDEVICES: CATEGORY_CONTEXT,
    ARTIFACT_TYPE_NETWORK_PROFILE: CATEGORY_CONTEXT,
    ARTIFACT_TYPE_NETWORK_INTERFACE: CATEGORY_CONTEXT,
    # RunKey/Service/ProxySettings are NOT listed here -- they default to
    # CATEGORY_TOR_DIRECT via ARTIFACT_CATEGORY.get(artifact_type, CATEGORY_TOR_DIRECT),
    # same as UserAssist/Amcache/etc. (see the "Phase 4" comment on their ARTIFACT_TYPE_*
    # constants above for why these three are tor-direct, unlike Phase 2/3's device/
    # network context types).
}
