"""Module A's contribution to the case report: turn registry findings into presentation context.

Mirrors modules/module_c_memory/report.py's split: this renders nothing itself (root-level
report.py owns the template and the HTML); it only prepares module_a's view of `details`
(what __init__.py's run() adapter put there) for the template.

Two real problems showed up in the first report generated from a real acquisition (not
synthetic test data): UserAssist returned exact duplicate entries (same path/stats/
timestamp reported twice — pipeline.py's regipy extraction stays untouched/unmodified
here; a real fact isn't supposed to be shown twice, so it's collapsed at presentation
time, same as analyzer.py's own _dedup_high_confidence() does for Module C), and the
three hive types were rendered as three disconnected flat dumps of full prose sentences
per row. The actual evidentiary value is in correlating them: UserAssist (GUI launch),
ShimCache (cache insertion), and Amcache (install/first-seen) are three *independent* OS
subsystems, and the same binary showing up in more than one of them is stronger evidence
than any single hive alone — see _build_component_timeline(). That correlation, and the
per-field values (run count, sha1, size, ...) it needs, are pulled out of each Artifact's
already-rendered `description` via regex rather than re-plumbing raw regipy fields through
pipeline.py/normalize.py/extractors.py — those stay exactly as already tested; only this
presentation layer changes. Confidence is read straight off each finding's own
Artifact.confidence field (set once, per artifact_type, in normalize.py from
constants.ARTIFACT_CONFIDENCE — see that module's "Confidence / category" section) rather
than a second map living here, as of Phase 0 of the Module A roadmap; section ordering
(ARTIFACT_TYPE_ORDER) is still a presentation-only choice made here.
"""

from __future__ import annotations

import re
from datetime import datetime

from .constants import CATEGORY_TOR_DIRECT, harddiskvolume_number, infer_drive_letters
from .narrative import (
    GLOSSARY,
    build_autostart_narrative,
    build_narrative,
    build_network_narrative,
    describe_portable_install_note,
    extract_drive_letter,
    find_install_location_path,
    find_latest_tor_use_iso,
)

# Strongest evidence first: UserAssist/Amcache/BAM/InstalledPrograms/CompatAssistantStore/
# FirefoxLauncher are HIGH confidence, ShimCache/MUICache/ShellBags/LastVisitedPidlMRU
# MEDIUM, RecentDocs/RunMRU/WordWheelQuery/ComDlg32/AppSwitched/TypedPaths LOW
# (contextual only) — see constants.py's ARTIFACT_CONFIDENCE for the per-type source of
# truth (this tuple is presentation ordering only, kept consistent with it by hand).
# RunKey/Service/ProxySettings (Phase 4) are HIGH confidence but evidence of
# CONFIGURATION, not of a run -- placed last: they corroborate deliberate, ongoing Tor
# use, but are weaker standalone evidence than an actual recorded execution above them.
ARTIFACT_TYPE_ORDER = (
    "UserAssist",
    "Amcache",
    "BAM",
    "InstalledPrograms",
    "CompatAssistantStore",
    "FirefoxLauncher",
    "ShimCache",
    "MUICache",
    "ShellBags",
    "LastVisitedPidlMRU",
    "RecentDocs",
    "RunMRU",
    "WordWheelQuery",
    "ComDlg32",
    "AppSwitched",
    "TypedPaths",
    "RunKey",
    "Service",
    "ProxySettings",
)
ARTIFACT_TYPE_LABELS = {
    "UserAssist": "UserAssist — GUI-launched execution",
    "Amcache": "Amcache — install / first-seen",
    "BAM": "BAM — last-execution record",
    "InstalledPrograms": "Installed Programs (Uninstall key)",
    "CompatAssistantStore": "Program Compatibility Assistant Store",
    "FirefoxLauncher": "Firefox Launcher",
    "ShimCache": "ShimCache / AppCompatCache",
    "MUICache": "MUICache — shell display names",
    "ShellBags": "ShellBags — folder-browsing history",
    "LastVisitedPidlMRU": "LastVisitedPidlMRU — program + last-browsed folder",
    "RecentDocs": "RecentDocs — contextual",
    "RunMRU": "RunMRU — Run dialog history",
    "WordWheelQuery": "WordWheelQuery — Explorer search history",
    "ComDlg32": "ComDlg32 — Open/Save dialog history",
    "AppSwitched": "AppSwitched — Alt+Tab/taskbar switches",
    "TypedPaths": "TypedPaths — Explorer address bar history",
    "RunKey": "Run / RunOnce — automatic start configuration",
    "Service": "Windows Service — automatic start configuration",
    "ProxySettings": "Internet Settings — proxy configuration",
}
# Confidence used to be independently restated here as a static per-type map, duplicating
# normalize.py's own prose-embedded "Confidence: ..." sentence. As of Phase 0 of the
# Module A roadmap, confidence is a structured field on each finding itself
# (Artifact.confidence, set once in normalize.py from constants.ARTIFACT_CONFIDENCE) --
# _section_confidence() below reads it directly instead of a second map.
HIVE_LABELS = {
    "ntuser": "NTUSER.DAT",
    "system": "SYSTEM",
    "amcache": "Amcache.hve",
    "software": "SOFTWARE",
    "usrclass": "UsrClass.dat",
}
# The three CATEGORY_CONTEXT artifact types (see constants.py) -- kept out of the
# tor-direct `sections` list entirely and surfaced separately via system_context() below.
CONTEXT_ARTIFACT_TYPES = ("ComputerName", "TimeZone", "WindowsVersion")
# Phase 2's six CATEGORY_CONTEXT device-evidence types -- also kept out of `sections`
# (ARTIFACT_TYPE_ORDER), surfaced instead via the dedicated devices appendix built by
# _build_device_correlation() below, same separation CONTEXT_ARTIFACT_TYPES already has.
DEVICE_ARTIFACT_TYPES = (
    "USBStor",
    "USBDevices",
    "MountedDevices",
    "MountPoints2",
    "EMDMgmt",
    "PortableDevices",
)
# Which of a component's "seen_in" sources actually corroborate EXECUTION (vs. merely
# contextual evidence) -- used by _build_component_timeline()'s "execution_sources" field
# and narrative.py's describe_evidence_strength()/describe_reliability() (the "N
# independent sources confirm Tor Browser was opened" claims). UserAssist/Amcache/
# ShimCache/BAM are the three-plus-one independent OS subsystems this module has always
# treated as execution evidence; MUICache is included too -- it's populated when the
# shell actually invokes a program, not merely by browsing to it -- but ShellBags is
# deliberately excluded: it only ever shows a folder was browsed in Explorer, never that
# anything inside it was executed, so it must not inflate an execution-corroboration
# count (a real bug this constant fixes -- see _build_component_timeline()'s docstring).
EXECUTION_SOURCE_TYPES = frozenset({"UserAssist", "Amcache", "ShimCache", "BAM", "MUICache"})

# normalize.py's own description formats, matched here rather than re-plumbed as raw
# fields — see module docstring. "for '...'" covers UserAssist/ShimCache/Amcache;
# "entry '...'" covers RecentDocs/MountedDevices/MountPoints2/EMDMgmt/PortableDevices;
# "device '...'" covers Phase 2's USBStor/USBDevices.
_PATH_RE = re.compile(r"(?:for|entry|device) '([^']+)'")
_RUN_COUNT_RE = re.compile(r"run_count=(\d+)")
_FOCUS_COUNT_RE = re.compile(r"focus_count=(\d+)")
_FOCUS_TIME_RE = re.compile(r"total_focus_time_ms=(\d+)")
_SHA1_RE = re.compile(r"sha1=([0-9a-fA-F]+)")
_SIZE_RE = re.compile(r"size=(\d+)")
_SID_RE = re.compile(r"sid=([\w-]+)")
# Phase 2 device-evidence fields -- normalize.py always renders these unconditionally
# (never an optional suffix that may be absent), so each regex can assume a match exists
# whenever its artifact_type is present; "unknown" is a real string value in that case,
# not a missing-match sentinel. Each field (other than the last one in its parenthesized
# group) must stop at the following comma, not the closing paren -- these are NOT
# necessarily the last field any more (e.g. USBSTOR's serial= is followed by
# first_connected=/last_connected=).
_MANUFACTURER_RE = re.compile(r"manufacturer=([^,]+),")
_SERIAL_RE = re.compile(r"serial=([^,]+),")
_FIRST_CONNECTED_RE = re.compile(r"first_connected=([^,]+),")
_LAST_CONNECTED_RE = re.compile(r"last_connected=([^)]+)\)")
_VID_RE = re.compile(r"vid=([^,]+),")
_PID_RE = re.compile(r"pid=([^)]+)\)")
_MOUNT_TYPE_RE = re.compile(r"mount_type=([^,]+),")
_DECODED_RE = re.compile(r"decoded=([^,]+),")
_VOLUME_GUID_RE = re.compile(r"volume_guid=([^)]+)\)")
_DEVICE_CAPACITY_RE = re.compile(r"device_capacity=([^)]+)\)")
_DEVICE_ID_RE = re.compile(r"device_id=([^)]+)\)")
# The serial number embedded in a USBSTOR-shaped device path/subkey-name, shared by
# MountedDevices' decoded value and MountPoints2/EMDMgmt's own subkey names -- e.g.
# "...USBSTOR#Disk&Ven_SanDisk&Prod_Cruzer_Blade&Rev_1.00#4C53...&0#{GUID}" -> "4C53...&0".
_DEVICE_SERIAL_FROM_PATH_RE = re.compile(r"#([^#]+)#\{[0-9a-fA-F-]+\}\s*$")

# Phase 3 (network context) description fields -- normalize.py always renders these
# unconditionally (never an optional suffix that may be absent), same convention as Phase
# 2's device-evidence fields above.
_NET_PROFILE_NAME_RE = re.compile(r"Network profile '([^']+)'")
_NET_PROFILE_TYPE_RE = re.compile(r"type=([^,]+),")
_NET_PROFILE_CATEGORY_RE = re.compile(r"category=([^,]+),")
_NET_PROFILE_CREATED_RE = re.compile(r"created_local=([^,]+),")
_NET_PROFILE_LAST_CONNECTED_RE = re.compile(r"last_connected_local=([^,]+),")
_NET_PROFILE_MAC_RE = re.compile(r"gateway_mac=([^,]+),")
_NET_PROFILE_DNS_SUFFIX_RE = re.compile(r"dns_suffix=([^)]+)\)")

_NET_IFACE_NAME_RE = re.compile(r"Network interface '([^']+)'")
_NET_IFACE_DHCP_RE = re.compile(r"dhcp=(yes|no)")
_NET_IFACE_IP_RE = re.compile(r"ip=([^,]+),")
_NET_IFACE_GATEWAY_RE = re.compile(r"gateway=([^,]+),")
_NET_IFACE_DHCP_SERVER_RE = re.compile(r"dhcp_server=([^,]+),")
_NET_IFACE_LEASE_OBTAINED_RE = re.compile(r"lease_obtained_utc=([^,]+),")
_NET_IFACE_LEASE_TERMINATES_RE = re.compile(r"lease_terminates_utc=([^,]+),")
_NET_IFACE_DOMAIN_RE = re.compile(r"domain=([^)]+)\)")

# Phase 4 (persistence/configuration) description fields.
_RUNKEY_VALUE_NAME_RE = re.compile(r"value name=('.*?'), key=")
_RUNKEY_KEY_PATH_RE = re.compile(r"key=([^)]+)\)")
_SERVICE_NAME_RE = re.compile(r"service name=('.*?')(?:, start=|\))")
_SERVICE_START_RE = re.compile(r"start=([^)]+)\)")
_PROXY_ENABLED_RE = re.compile(r"enabled=(yes|no)")
_PROXY_SERVER_RE = re.compile(r"server=([^,]+),")
_PROXY_AUTOCONFIG_RE = re.compile(r"auto_config_url=([^)]+)\)")


def _extract_path(description: str) -> str | None:
    match = _PATH_RE.search(description)
    return match.group(1) if match else None


def _none_if_unknown(value: str, sentinel: str = "unknown") -> str | None:
    """normalize.py renders several Phase 2 fields unconditionally with a literal
    "unknown"/"none" sentinel string rather than omitting them, so every regex above can
    assume a match always exists (see the module-level comment on those regexes). Once
    extracted here, the sentinel is converted back to a real `None` so downstream
    presentation code (e.g. "serial {serial}" clauses) doesn't literally print the word
    "unknown" as if it were a value read from the registry."""
    return None if value == sentinel else value


def _basename(path: str) -> str:
    return path.replace("/", "\\").rsplit("\\", 1)[-1].lower()


def _is_tor_direct(finding: dict) -> bool:
    """True unless this finding is explicitly category="context" (ComputerName/TimeZone/
    WindowsVersion, or Phase 2's six device-evidence types). Defaults to True for a
    finding with no "category" key at all (an older hand-built test fixture that never
    went through normalize.py) -- same default normalize.py itself uses for
    Artifact.category. Confirmed root cause of a real bug: Phase 2 widened _PATH_RE to
    give every device-evidence type a "path" field too, and _build_component_timeline()
    below used to iterate every artifact_type unconditionally -- so every USB device,
    drive letter and MountedDevices/MountPoints2 entry was being treated as a "Tor
    Browser component" the moment any one of them had a path-shaped description. This is
    the single choke point that keeps context-category findings out of anywhere this
    module infers Tor-related facts from "all known paths"."""
    return finding.get("category", CATEGORY_TOR_DIRECT) == CATEGORY_TOR_DIRECT


def _parse_timestamp(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value)
    except ValueError:
        return None


def _dedupe(findings: list[dict]) -> list[dict]:
    """Collapse byte-identical entries (same description+source+timestamp). Seen for
    real: UserAssist reporting the same launch twice. A real fact isn't supposed to be
    shown twice; tracks how many times it actually appeared via `occurrences` rather
    than silently dropping the count information."""
    seen: dict[tuple, dict] = {}
    order: list[tuple] = []
    for finding in findings:
        key = (finding["description"], finding["source"], finding["timestamp"])
        if key not in seen:
            seen[key] = {**finding, "occurrences": 1}
            order.append(key)
        else:
            seen[key]["occurrences"] += 1
    return [seen[key] for key in order]


def _annotate(findings: list[dict], artifact_type: str) -> list[dict]:
    """Pull structured fields (path, run stats, hash/size) out of each finding's
    rendered description so the report can show real table columns instead of one long
    prose sentence per row."""
    annotated = []
    for finding in findings:
        entry = {**finding, "path": _extract_path(finding["description"])}
        if artifact_type == "UserAssist":
            m = _RUN_COUNT_RE.search(finding["description"])
            entry["run_count"] = int(m.group(1)) if m else None
            m = _FOCUS_COUNT_RE.search(finding["description"])
            entry["focus_count"] = int(m.group(1)) if m else None
            m = _FOCUS_TIME_RE.search(finding["description"])
            entry["total_focus_time_ms"] = int(m.group(1)) if m else None
        elif artifact_type == "Amcache":
            m = _SHA1_RE.search(finding["description"])
            entry["sha1"] = m.group(1) if m else None
            m = _SIZE_RE.search(finding["description"])
            entry["size"] = int(m.group(1)) if m else None
        elif artifact_type == "BAM":
            m = _SID_RE.search(finding["description"])
            entry["sid"] = m.group(1) if m else None
        elif artifact_type == "USBStor":
            m = _MANUFACTURER_RE.search(finding["description"])
            entry["manufacturer"] = _none_if_unknown(m.group(1)) if m else None
            m = _SERIAL_RE.search(finding["description"])
            entry["serial_number"] = _none_if_unknown(m.group(1)) if m else None
            m = _FIRST_CONNECTED_RE.search(finding["description"])
            entry["first_connected"] = _none_if_unknown(m.group(1)) if m else None
            m = _LAST_CONNECTED_RE.search(finding["description"])
            entry["last_connected"] = _none_if_unknown(m.group(1)) if m else None
        elif artifact_type == "USBDevices":
            m = _VID_RE.search(finding["description"])
            entry["vid"] = m.group(1) if m else None
            m = _PID_RE.search(finding["description"])
            entry["pid"] = m.group(1) if m else None
        elif artifact_type == "MountedDevices":
            m = _MOUNT_TYPE_RE.search(finding["description"])
            entry["mount_type"] = m.group(1) if m else None
            m = _DECODED_RE.search(finding["description"])
            entry["decoded"] = m.group(1) if m else None
            m = _VOLUME_GUID_RE.search(finding["description"])
            entry["volume_guid"] = _none_if_unknown(m.group(1), sentinel="none") if m else None
        elif artifact_type == "EMDMgmt":
            m = _DEVICE_CAPACITY_RE.search(finding["description"])
            entry["device_capacity"] = m.group(1) if m else None
        elif artifact_type == "PortableDevices":
            m = _DEVICE_ID_RE.search(finding["description"])
            entry["device_id"] = m.group(1) if m else None
        elif artifact_type == "NetworkProfile":
            m = _NET_PROFILE_NAME_RE.search(finding["description"])
            entry["profile_name"] = m.group(1) if m else None
            m = _NET_PROFILE_TYPE_RE.search(finding["description"])
            entry["name_type"] = _none_if_unknown(m.group(1)) if m else None
            m = _NET_PROFILE_CATEGORY_RE.search(finding["description"])
            entry["category"] = _none_if_unknown(m.group(1)) if m else None
            m = _NET_PROFILE_CREATED_RE.search(finding["description"])
            entry["created_local"] = _none_if_unknown(m.group(1)) if m else None
            m = _NET_PROFILE_LAST_CONNECTED_RE.search(finding["description"])
            entry["last_connected_local"] = _none_if_unknown(m.group(1)) if m else None
            m = _NET_PROFILE_MAC_RE.search(finding["description"])
            entry["gateway_mac"] = _none_if_unknown(m.group(1)) if m else None
            m = _NET_PROFILE_DNS_SUFFIX_RE.search(finding["description"])
            entry["dns_suffix"] = _none_if_unknown(m.group(1)) if m else None
        elif artifact_type == "NetworkInterface":
            m = _NET_IFACE_NAME_RE.search(finding["description"])
            entry["interface_name"] = m.group(1) if m else None
            m = _NET_IFACE_DHCP_RE.search(finding["description"])
            entry["dhcp_enabled"] = m.group(1) == "yes" if m else None
            m = _NET_IFACE_IP_RE.search(finding["description"])
            entry["ip"] = _none_if_unknown(m.group(1)) if m else None
            m = _NET_IFACE_GATEWAY_RE.search(finding["description"])
            entry["gateway"] = _none_if_unknown(m.group(1)) if m else None
            m = _NET_IFACE_DHCP_SERVER_RE.search(finding["description"])
            entry["dhcp_server"] = _none_if_unknown(m.group(1)) if m else None
            m = _NET_IFACE_LEASE_OBTAINED_RE.search(finding["description"])
            entry["lease_obtained_utc"] = _none_if_unknown(m.group(1)) if m else None
            m = _NET_IFACE_LEASE_TERMINATES_RE.search(finding["description"])
            entry["lease_terminates_utc"] = _none_if_unknown(m.group(1)) if m else None
            m = _NET_IFACE_DOMAIN_RE.search(finding["description"])
            entry["domain"] = _none_if_unknown(m.group(1)) if m else None
        elif artifact_type == "RunKey":
            m = _RUNKEY_VALUE_NAME_RE.search(finding["description"])
            entry["value_name"] = m.group(1).strip("'") if m else None
            m = _RUNKEY_KEY_PATH_RE.search(finding["description"])
            entry["key_path"] = m.group(1) if m else None
        elif artifact_type == "Service":
            m = _SERVICE_NAME_RE.search(finding["description"])
            entry["service_name"] = m.group(1).strip("'") if m else None
            m = _SERVICE_START_RE.search(finding["description"])
            entry["start"] = m.group(1) if m else None
        elif artifact_type == "ProxySettings":
            m = _PROXY_ENABLED_RE.search(finding["description"])
            entry["proxy_enabled"] = m.group(1) == "yes" if m else None
            m = _PROXY_SERVER_RE.search(finding["description"])
            entry["proxy_server"] = _none_if_unknown(m.group(1)) if m else None
            m = _PROXY_AUTOCONFIG_RE.search(finding["description"])
            entry["auto_config_url"] = _none_if_unknown(m.group(1), sentinel="none") if m else None
        annotated.append(entry)
    return annotated


def _build_component_timeline(annotated_by_type: dict[str, list[dict]]) -> list[dict]:
    """Cross-hive correlation, keyed by basename: what does each of the three
    independent hive sources say about the SAME binary? UserAssist/ShimCache/Amcache are
    different OS subsystems recording different things (GUI launch, cache insertion,
    install) about what's very often the same file -- seeing them agree is stronger
    evidence than any one alone, and is the actual finding a flat per-hive dump misses.

    Only iterates tor-direct findings (`_is_tor_direct()`) -- a real, confirmed bug this
    fixes: Phase 2 widened _PATH_RE so every device-evidence type (USB/MountedDevices/
    MountPoints2/etc.) also gets a `path` field, and this function used to iterate every
    artifact_type in `annotated_by_type` unconditionally, so every USB device, drive
    letter and volume GUID on the machine was being treated as a "Tor Browser component"
    the moment it had a path-shaped description -- confirmed against a real acquisition
    (58 "distinct files" where only 8 were genuinely Tor-related).

    `seen_in` lists every source that mentioned this basename (still useful context, e.g.
    "this file was also browsed to in Explorer"); `execution_sources` is the subset of
    those in EXECUTION_SOURCE_TYPES -- the one used for "N independent sources confirm
    execution" claims (narrative.py's describe_evidence_strength()/describe_reliability(),
    and this module's own `corroborated_components` count below), since ShellBags showing
    up in `seen_in` must never inflate that specific claim.
    """
    components: dict[str, dict] = {}
    for artifact_type, findings in annotated_by_type.items():
        for finding in findings:
            if not _is_tor_direct(finding):
                continue
            path = finding.get("path")
            if not path:
                continue
            key = _basename(path)
            component = components.setdefault(key, {"basename": key, "paths": set(), "sources": {}})
            component["paths"].add(path)
            component["sources"].setdefault(artifact_type, []).append(finding)

    def type_rank(artifact_type: str) -> int:
        return (
            ARTIFACT_TYPE_ORDER.index(artifact_type) if artifact_type in ARTIFACT_TYPE_ORDER else 99
        )

    timeline = []
    for component in components.values():
        sources = component["sources"]
        amcache_ts = [_parse_timestamp(f["timestamp"]) for f in sources.get("Amcache", [])]
        userassist_ts = [_parse_timestamp(f["timestamp"]) for f in sources.get("UserAssist", [])]
        bam_ts = [_parse_timestamp(f["timestamp"]) for f in sources.get("BAM", [])]
        userassist_last_run = max((t for t in userassist_ts if t), default=None)
        bam_last_run = max((t for t in bam_ts if t), default=None)
        # Merges UserAssist's and BAM's last-run times into one "Last activity" column
        # (with a small source tag) instead of two near-identical timestamp columns --
        # see the Technical details section's own note for why these two can differ by
        # a few seconds and still describe the same use.
        last_activity_candidates = [
            (ts, label)
            for ts, label in ((userassist_last_run, "UserAssist"), (bam_last_run, "BAM"))
            if ts
        ]
        last_activity = None
        if last_activity_candidates:
            ts, source = max(last_activity_candidates)
            last_activity = {"timestamp": ts, "source": source}
        timeline.append(
            {
                "basename": component["basename"],
                "paths": sorted(component["paths"]),
                "seen_in": sorted(sources.keys(), key=type_rank),
                "execution_sources": sorted(
                    (s for s in sources if s in EXECUTION_SOURCE_TYPES), key=type_rank
                ),
                "amcache_first_seen": min((t for t in amcache_ts if t), default=None),
                "userassist_run_count": sum(
                    f.get("run_count") or 0 for f in sources.get("UserAssist", [])
                ),
                "userassist_last_run": userassist_last_run,
                "shimcache_hits": len(sources.get("ShimCache", [])),
                "bam_last_run": bam_last_run,
                "last_activity": last_activity,
            }
        )
    # Strongest evidence first: more independent sources agreeing > fewer; ties broken by name.
    timeline.sort(key=lambda c: (-len(c["seen_in"]), c["basename"]))
    return timeline


def _find_linked_launches(annotated_by_type: dict[str, list[dict]]) -> list[dict]:
    """UserAssist entries that fired at the exact same recorded instant are very likely
    one user action viewed from two angles (e.g. a .lnk shortcut and the .exe it
    launched) -- not independent corroboration (both come from the same hive/subsystem),
    but still a link a reader would otherwise only notice by eye-comparing timestamps
    across unrelated-looking rows (see e.g. "Tor Browser.lnk" and "firefox.exe" sharing a
    timestamp in a real acquisition). Grouped and sorted explicitly so this is as
    repeatable as the rest of the presentation layer -- never relies on dict/set order.
    """
    basenames_by_timestamp: dict[str, set[str]] = {}
    paths_by_timestamp: dict[str, list[str]] = {}
    for finding in annotated_by_type.get("UserAssist", []):
        timestamp = finding.get("timestamp")
        path = finding.get("path")
        if not timestamp or not path:
            continue
        seen_basenames = basenames_by_timestamp.setdefault(timestamp, set())
        basename = _basename(path)
        if basename not in seen_basenames:
            seen_basenames.add(basename)
            paths_by_timestamp.setdefault(timestamp, []).append(path)

    linked = [
        {"timestamp": timestamp, "paths": sorted(paths)}
        for timestamp, paths in paths_by_timestamp.items()
        if len(basenames_by_timestamp[timestamp]) > 1
    ]
    linked.sort(key=lambda entry: entry["timestamp"])
    return linked


def _quiet_hive_notes(hives_provided: dict, annotated_by_type: dict[str, list[dict]]) -> list[str]:
    """A component showing no Amcache/ShimCache hits isn't necessarily evidence those
    subsystems never saw Tor -- both have reasons to stay silent that have nothing to do
    with whether Tor ran. Surfaced explicitly here instead of leaving a reader to infer
    it from a bare "—" in the component table."""
    notes = []
    if hives_provided.get("amcache") and not annotated_by_type.get("Amcache"):
        notes.append(
            "Amcache.hve was supplied but contained no Tor-related entries. Amcache is "
            "populated by Windows' periodic Compatibility Appraiser scan, not at install "
            "or run time — this usually means that scan hasn't run since the activity "
            "above, not that Tor wasn't used."
        )
    if hives_provided.get("system") and not annotated_by_type.get("ShimCache"):
        notes.append(
            "SYSTEM was supplied but contained no Tor-related ShimCache entries. "
            "ShimCache is a bounded, insertion-order cache that reboots or other "
            "activity can evict entries from — its absence doesn't rule out execution."
        )
    if hives_provided.get("system") and not annotated_by_type.get("BAM"):
        notes.append(
            "SYSTEM was supplied but contained no Tor-related BAM entries. BAM "
            "(Background Activity Moderator) only exists from Windows 10 1709 onward "
            "— its absence doesn't rule out execution on an older or unaffected system."
        )
    portable_note = describe_portable_install_note(bool(annotated_by_type.get("InstalledPrograms")))
    if hives_provided.get("software") and portable_note:
        notes.append(portable_note)
    return notes


def _build_extraction_warnings(warnings: list[dict]) -> list[str]:
    """Plain-English counterpart to the technical `details["warnings"]` list (see
    core.schema.ModuleResult's docstring and __init__.py's run()) -- one fixed,
    deterministic sentence per failed artifact type, same "no LLM, every sentence traces
    to one rule" convention narrative.py uses throughout. Deliberately does NOT include
    the raw exception text (that stays in the technical warning / findings.json / logs,
    for examiners) -- a non-technical reader only needs to know what didn't come
    through and that everything else is still trustworthy."""
    sentences = []
    for warning in warnings:
        artifact_type = warning.get("artifact_type", "")
        label = ARTIFACT_TYPE_LABELS.get(artifact_type, artifact_type)
        friendly = label.split(" — ")[0]
        sentences.append(
            f"{friendly} could not be read due to a parser error; other registry "
            "evidence in this report is unaffected."
        )
    return sentences


def _section_confidence(findings: list[dict]) -> str:
    """Every finding of one artifact_type shares the same confidence by construction
    (normalize.py assigns it once per artifact_type -- see constants.ARTIFACT_CONFIDENCE),
    so the first finding is representative. "unknown" is only reached by a hand-built
    details dict that never went through normalize.py (e.g. an older test fixture)."""
    if findings and findings[0].get("confidence"):
        return findings[0]["confidence"]
    return "unknown"


def _build_system_context(findings_by_type: dict[str, list[dict]]) -> dict:
    """Computer name / time zone / Windows version -- CATEGORY_CONTEXT findings (see
    constants.py), kept out of the tor-direct `sections` list entirely since they were
    never filtered by is_tor_related() and aren't Tor evidence themselves. Structured
    only, for now -- no narrative/template prose wired up yet (that's Phase 5 of the
    Module A roadmap); this just makes the facts available to whatever renders next."""
    context: dict = {}
    for artifact_type in CONTEXT_ARTIFACT_TYPES:
        findings = findings_by_type.get(artifact_type) or []
        if findings:
            context[artifact_type] = findings[0]
    return context


_TZ_BIAS_RE = re.compile(r"bias=(-?\d+) minutes from UTC")


def _extract_timezone_bias(system_context: dict) -> int | None:
    """Pulls the system's own recorded UTC bias (minutes) back out of TimeZone's
    normalized description -- the only place it's available from this layer (see this
    module's docstring on why structured fields are regex-parsed from `description`
    rather than re-plumbed through pipeline.py/normalize.py). Returns None when TimeZone
    wasn't found at all, or has no bias recorded -- callers must treat that as "unknown",
    never default to 0 (UTC), which would silently claim a specific, wrong time zone."""
    tz_finding = system_context.get("TimeZone")
    if not tz_finding:
        return None
    match = _TZ_BIAS_RE.search(tz_finding.get("description", ""))
    return int(match.group(1)) if match else None


def _build_network_context(
    annotated_by_type: dict[str, list[dict]],
    system_context: dict,
    latest_tor_use_iso: str | None,
) -> dict:
    """Phase 3's "Network context at time of use" section -- NetworkProfile/
    NetworkInterface are CATEGORY_CONTEXT (see constants.py), kept out of the tor-direct
    `sections` list entirely, same treatment as system_context's three Phase 0 facts and
    Phase 2's device appendix. `bias_minutes` (the system's own recorded UTC offset, if
    known) is what lets build_network_narrative() convert NetworkList's local-time
    timestamps to UTC for comparison against the Tor launch instant -- see
    narrative.local_systemtime_to_utc()'s docstring for why this must be the TARGET
    machine's own recorded bias, not the examiner's `local_tz` display preference."""
    profiles = annotated_by_type.get("NetworkProfile", [])
    interfaces = annotated_by_type.get("NetworkInterface", [])
    bias_minutes = _extract_timezone_bias(system_context)
    return {
        "profiles": profiles,
        "interfaces": interfaces,
        "bias_minutes": bias_minutes,
        "narrative": build_network_narrative(
            profiles, interfaces, bias_minutes, latest_tor_use_iso
        ),
    }


def _build_autostart_context(annotated_by_type: dict[str, list[dict]]) -> dict:
    """Phase 4's "Automatic start and proxy settings" section. RunKey/Service/
    ProxySettings are CATEGORY_TOR_DIRECT (see constants.py) and only ever present when
    they already reference Tor (is_tor_related_entry()'s special cases for these three
    types) -- so unlike system_context/network_context there's no extra "only kept
    alongside a tor-direct finding" gate needed here; these ARE the tor-direct findings.
    Empty narrative (not a missing key) when there's nothing to say, so the template can
    decide whether to render the section at all."""
    run_keys = annotated_by_type.get("RunKey", [])
    services = annotated_by_type.get("Service", [])
    proxy_settings = annotated_by_type.get("ProxySettings", [])
    return {
        "run_keys": run_keys,
        "services": services,
        "proxy_settings": proxy_settings,
        "narrative": build_autostart_narrative(run_keys, services, proxy_settings),
    }


# Artifact types "Files involved" (Phase 5) draws from -- every one of these is already
# is_tor_related_entry()-filtered at the pipeline level (CATEGORY_TOR_DIRECT), so no
# further relevance filtering is needed here; this just merges three separate per-hive
# tables into one plain-English "what files were touched" view.
_FILES_INVOLVED_TYPES = ("ComDlg32", "RecentDocs", "ShellBags")


def _build_files_involved(annotated_by_type: dict[str, list[dict]]) -> list[dict]:
    files = [
        {
            "path": finding.get("path"),
            "source": artifact_type,
            "timestamp": finding.get("timestamp"),
        }
        for artifact_type in _FILES_INVOLVED_TYPES
        for finding in annotated_by_type.get(artifact_type, [])
        if finding.get("path")
    ]
    files.sort(key=lambda f: f["timestamp"] or "")
    return files


def _build_profiles_table(profiles: list[dict], relevant_sid: str | None) -> list[dict]:
    """Reference table of every Windows user profile on the machine (SID -> username ->
    profile path), from SOFTWARE's ProfileList -- not a Tor-relevance finding, just
    context for "which account is this activity under" and for narrative.py's SID
    resolution. `relevant_sid` (BAM's resolved SID, if any) flags the one profile tied to
    the Tor activity above, via `is_relevant`, so the report's appendix can highlight it
    and fold the rest behind a "show all profiles" toggle rather than presenting every
    account on the machine as equally significant. Sorted by profile path for
    deterministic, repeatable output."""
    rows = [
        {
            "sid": profile.get("sid"),
            "path": profile.get("path"),
            "last_write": profile.get("last_write"),
            "is_relevant": bool(relevant_sid) and profile.get("sid") == relevant_sid,
        }
        for profile in profiles
        if profile.get("path")
    ]
    rows.sort(key=lambda row: row["path"])
    return rows


def _annotate_harddiskvolume_notes(
    annotated_by_type: dict[str, list[dict]], drive_inferences: dict[str, str]
) -> None:
    """A path like "\\Device\\HarddiskVolume6\\Tor Browser\\..." is Windows' own internal
    volume name, not a drive letter -- mutates each finding whose path has this shape to
    carry a plain explanatory note, resolved via `drive_inferences` (see
    constants.infer_drive_letters' docstring for why MountedDevices can't answer this and
    same-evidence correlation is used instead) when possible, and an honest "could not be
    determined" note otherwise. Explained here, once, rather than per-table."""
    for findings in annotated_by_type.values():
        for finding in findings:
            path = finding.get("path")
            volume_number = harddiskvolume_number(path) if path else None
            if not volume_number:
                continue
            letter = drive_inferences.get(path)
            if letter:
                finding["harddiskvolume_note"] = (
                    f"Windows recorded this as volume HarddiskVolume{volume_number} — its "
                    f"internal name for a storage volume. It very likely corresponds to "
                    f"{letter}: because the same file also appears as {letter}:\\... in "
                    "another record (an inference, not a value read directly from the "
                    "registry)."
                )
            else:
                finding["harddiskvolume_note"] = (
                    f"Windows recorded this as volume HarddiskVolume{volume_number} — its "
                    "internal name for a storage volume. The matching drive letter could "
                    "not be determined from the available registry data."
                )


def _build_device_correlation(
    annotated_by_type: dict[str, list[dict]], install_drive_letter: str | None
) -> dict:
    """Maps the Tor install's drive letter directly to a physical device, when possible,
    by decoding SYSTEM's MountedDevices entry for that letter and joining its embedded
    USBSTOR-shaped serial number against USBSTOR/MountPoints2/EMDMgmt/PortableDevices
    findings -- a real structural correlation (the same serial number independently
    present in multiple OS subsystems), not the coincidental same-evidence path-suffix
    guessing constants.infer_drive_letters() does for a different problem
    (HarddiskVolumeN -> letter, kept unchanged). Modeled on _build_profiles_table()'s
    is_relevant flagging: nothing is discarded -- every USBStor/USBDevices/
    MountedDevices/MountPoints2/EMDMgmt/PortableDevices row the machine has ever recorded
    is still returned, just with the one (or few) rows tied to the Tor install's own
    drive letter flagged `is_relevant` rather than presented as equally significant as
    the machine's entire USB history.

    Resolution chain, strongest/most-specific first:
    1. The drive-letter's own MountedDevices value is a Windows Dynamic Disk identifier
       ("DMIO:ID:...", see extractors.extract_mounted_devices()) -- Windows does not
       support dynamic disks on removable USB media, so this is itself real, structural
       evidence the drive is a fixed/internal-disk partition, not a USB stick. Resolution
       stops here (device_info["dynamic_disk"] = True); no USBSTOR/PortableDevices
       matching is attempted and no candidates are offered.
    2. The decoded value directly names a USBSTOR-shaped path -- extract its serial via
       _DEVICE_SERIAL_FROM_PATH_RE and match against USBStor/PortableDevices.
    3. The decoded value instead names a bare \\??\\Volume{GUID} -- look for another
       MountedDevices entry whose own mount_point is exactly that \\??\\Volume{GUID}
       string (same decode, different value), and retry step 2 against it. Exact
       value-name match only -- no fuzzy/near-GUID matching (proven to be a dead end:
       USBSTOR's own disk_guid never matches a real MountedDevices volume GUID on
       verified real evidence).
    4. Neither: device_info carries no name and no dynamic_disk -- the caller states
       plainly the device could not be identified and offers every USBStor/
       PortableDevices entry on the machine as a "possible candidate" (never USBDevices
       hubs/cameras/sensors, never MountPoints2/EMDMgmt).
    """
    mounted_rows = annotated_by_type.get("MountedDevices", [])
    usbstor_rows = annotated_by_type.get("USBStor", [])
    portable_rows = annotated_by_type.get("PortableDevices", [])
    mountpoints2_rows = annotated_by_type.get("MountPoints2", [])
    emdmgmt_rows = annotated_by_type.get("EMDMgmt", [])
    usb_devices_rows = annotated_by_type.get("USBDevices", [])

    direct_row = None
    if install_drive_letter:
        target = f"{install_drive_letter}:"
        for row in mounted_rows:
            row["is_relevant"] = row.get("path") == target
            if row["is_relevant"]:
                direct_row = row
    else:
        for row in mounted_rows:
            row["is_relevant"] = False

    dynamic_disk = False
    device_serial: str | None = None
    if direct_row is not None:
        if direct_row.get("decoded") == "dynamic_disk_identifier":
            dynamic_disk = True
        else:
            match = _DEVICE_SERIAL_FROM_PATH_RE.search(direct_row.get("decoded") or "")
            if match:
                device_serial = match.group(1)
            elif direct_row.get("volume_guid"):
                # Volume-GUID hop: a sibling MountedDevices entry literally named
                # "\??\Volume{<that GUID>}" may carry the USBSTOR-shaped decode instead.
                hop_name = f"\\??\\Volume{direct_row['volume_guid']}"
                hop_row = next((r for r in mounted_rows if r.get("path") == hop_name), None)
                if hop_row is not None:
                    hop_row["is_relevant"] = True
                    hop_match = _DEVICE_SERIAL_FROM_PATH_RE.search(hop_row.get("decoded") or "")
                    if hop_match:
                        device_serial = hop_match.group(1)

    matched_device: dict | None = None
    matched_kind: str | None = None
    for row in usbstor_rows:
        row["is_relevant"] = bool(device_serial) and row.get("serial_number") == device_serial
        if row["is_relevant"] and matched_device is None:
            matched_device = row
            matched_kind = "usbstor"

    for row in portable_rows:
        row["is_relevant"] = bool(device_serial) and device_serial in (row.get("device_id") or "")
        if row["is_relevant"] and matched_device is None:
            matched_device = row
            matched_kind = "portable"

    for row in mountpoints2_rows:
        row["is_relevant"] = bool(device_serial) and device_serial in (row.get("path") or "")
    for row in emdmgmt_rows:
        row["is_relevant"] = bool(device_serial) and device_serial in (row.get("path") or "")

    # USBDevices (generic enumeration -- hubs/cameras/sensors/etc.) has no serial-shaped
    # identifier to join on and is never a candidate either (see item 2's own wording).
    for row in usb_devices_rows:
        row["is_relevant"] = False

    device_info = None
    if install_drive_letter:
        device_info = {
            "drive_letter": install_drive_letter,
            "name": matched_device.get("path") if matched_device else None,
            "serial": (matched_device.get("serial_number") if matched_kind == "usbstor" else None),
            "first_connected": (
                matched_device.get("first_connected") if matched_kind == "usbstor" else None
            ),
            "last_connected": (
                matched_device.get("last_connected") if matched_kind == "usbstor" else None
            ),
            "dynamic_disk": dynamic_disk,
            "candidates": (
                []
                if (matched_device is not None or dynamic_disk)
                else [
                    {
                        "name": row.get("path"),
                        "serial": row.get("serial_number"),
                        "last_connected": row.get("last_connected"),
                    }
                    for row in usbstor_rows
                ]
                + [
                    {"name": row.get("path"), "serial": None, "last_connected": None}
                    for row in portable_rows
                ]
            ),
        }

    return {
        "install_drive_letter": install_drive_letter,
        "device_match": device_info,
        "usbstor": usbstor_rows,
        "usb_devices": usb_devices_rows,
        "mounted_devices": mounted_rows,
        "mountpoints2": mountpoints2_rows,
        "emdmgmt": emdmgmt_rows,
        "portable_devices": portable_rows,
    }


def build_context(details: dict, local_tz: str | None = None) -> dict:
    """Presentation context for the registry section of the case report.

    `local_tz` is an IANA zone name (e.g. "Asia/Colombo"), already resolved by the root
    report.py (auto-detected or explicitly configured) -- passed through uniformly to
    every module's build_context() even though only the plain-English narrative uses it
    today, so Module B/C can adopt the same parameter later without a signature change.
    """
    findings_by_type = details.get("findings_by_type", {})
    annotated_by_type = {
        artifact_type: _dedupe(_annotate(findings, artifact_type))
        for artifact_type, findings in findings_by_type.items()
    }

    sections = [
        {
            "type": artifact_type,
            "label": ARTIFACT_TYPE_LABELS.get(artifact_type, artifact_type),
            "confidence": _section_confidence(annotated_by_type[artifact_type]),
            "findings": annotated_by_type[artifact_type],
        }
        for artifact_type in ARTIFACT_TYPE_ORDER
        if annotated_by_type.get(artifact_type)
    ]

    component_timeline = _build_component_timeline(annotated_by_type)
    hives_provided = details.get("hives_provided", {})
    linked_launches = _find_linked_launches(annotated_by_type)
    quiet_hive_notes = _quiet_hive_notes(hives_provided, annotated_by_type)

    # Best-effort \Device\HarddiskVolumeN -> drive letter, inferred from the same
    # evidence set (see constants.infer_drive_letters) -- computed over every path this
    # report already knows about, then annotated onto the findings that need it.
    all_known_paths = {p for c in component_timeline for p in c["paths"]}
    drive_inferences = infer_drive_letters(all_known_paths)
    _annotate_harddiskvolume_notes(annotated_by_type, drive_inferences)

    # BAM's `sid` is the one authoritative link from "this activity" to "this Windows
    # profile" -- reused both by narrative.py's account resolution and here, to flag
    # the one relevant row in the profiles appendix.
    bam_sid = next((f.get("sid") for f in annotated_by_type.get("BAM", []) if f.get("sid")), None)
    profiles = _build_profiles_table(details.get("profiles", []), bam_sid)

    # Phase 2: resolve the Tor install's drive letter *before* build_narrative() runs (it
    # needs the letter to build install_drive_letter itself) so device correlation can
    # hand build_narrative() a direct device match to fold into the install-location
    # sentence -- see narrative.find_install_location_path()'s docstring for why this is
    # a second, independent call rather than threading build_narrative()'s internal state
    # out.
    install_drive_letter = extract_drive_letter(find_install_location_path(annotated_by_type))
    devices = _build_device_correlation(annotated_by_type, install_drive_letter)

    system_context = _build_system_context(findings_by_type)
    # Phase 3: resolve the Tor launch instant *before* build_narrative() runs, same
    # "second, independent call" precedent as install_drive_letter above (see
    # narrative.find_latest_tor_use_iso()'s own docstring) -- network correlation needs it
    # to compare against NetworkList/DHCP timestamps.
    latest_tor_use_iso = find_latest_tor_use_iso(annotated_by_type, component_timeline)
    network_context = _build_network_context(annotated_by_type, system_context, latest_tor_use_iso)
    autostart_context = _build_autostart_context(annotated_by_type)
    files_involved = _build_files_involved(annotated_by_type)

    return {
        "details": details,
        "summary": details.get("summary", ""),
        "errors": details.get("errors", []),
        "hives_analyzed": [HIVE_LABELS[k] for k, provided in hives_provided.items() if provided],
        "hives_missing": [HIVE_LABELS[k] for k, provided in hives_provided.items() if not provided],
        "sections": sections,
        "total_findings": sum(len(s["findings"]) for s in sections),
        "component_timeline": component_timeline,
        "corroborated_components": sum(
            1 for c in component_timeline if len(c["execution_sources"]) > 1
        ),
        "linked_launches": linked_launches,
        "quiet_hive_notes": quiet_hive_notes,
        "extraction_warnings": _build_extraction_warnings(details.get("warnings", [])),
        "profiles": profiles,
        "system_context": system_context,
        "network_context": network_context,
        "autostart_context": autostart_context,
        "files_involved": files_involved,
        "devices": devices,
        "narrative": build_narrative(
            annotated_by_type,
            component_timeline,
            linked_launches,
            quiet_hive_notes,
            profiles,
            local_tz,
            devices["device_match"],
        ),
        "glossary": GLOSSARY,
    }
