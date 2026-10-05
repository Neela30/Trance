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
presentation layer changes. Confidence levels/ordering restate what normalize.py already
decided per artifact type (2.4 of the project brief) — not a second interpretation.
"""

from __future__ import annotations

import re
from datetime import datetime

from .constants import harddiskvolume_number, infer_drive_letters
from .narrative import GLOSSARY, build_narrative

# Strongest evidence first: UserAssist/Amcache/BAM/InstalledPrograms are HIGH confidence,
# ShimCache/MUICache MEDIUM, RecentDocs/RunMRU/WordWheelQuery/ComDlg32 LOW (contextual
# only) — see normalize.py's own docstring for the per-type reasoning.
ARTIFACT_TYPE_ORDER = (
    "UserAssist",
    "Amcache",
    "BAM",
    "InstalledPrograms",
    "ShimCache",
    "MUICache",
    "RecentDocs",
    "RunMRU",
    "WordWheelQuery",
    "ComDlg32",
)
ARTIFACT_TYPE_LABELS = {
    "UserAssist": "UserAssist — GUI-launched execution",
    "Amcache": "Amcache — install / first-seen",
    "BAM": "BAM — last-execution record",
    "InstalledPrograms": "Installed Programs (Uninstall key)",
    "ShimCache": "ShimCache / AppCompatCache",
    "MUICache": "MUICache — shell display names",
    "RecentDocs": "RecentDocs — contextual",
    "RunMRU": "RunMRU — Run dialog history",
    "WordWheelQuery": "WordWheelQuery — Explorer search history",
    "ComDlg32": "ComDlg32 — Open/Save dialog history",
}
CONFIDENCE_BY_TYPE = {
    "UserAssist": "high",
    "Amcache": "high",
    "BAM": "high",
    "InstalledPrograms": "high",
    "ShimCache": "medium",
    "MUICache": "medium",
    "RecentDocs": "low",
    "RunMRU": "low",
    "WordWheelQuery": "low",
    "ComDlg32": "low",
}
HIVE_LABELS = {
    "ntuser": "NTUSER.DAT",
    "system": "SYSTEM",
    "amcache": "Amcache.hve",
    "software": "SOFTWARE",
}

# normalize.py's own description formats, matched here rather than re-plumbed as raw
# fields — see module docstring. "for '...'" covers UserAssist/ShimCache/Amcache;
# "entry '...'" covers RecentDocs.
_PATH_RE = re.compile(r"(?:for|entry) '([^']+)'")
_RUN_COUNT_RE = re.compile(r"run_count=(\d+)")
_FOCUS_COUNT_RE = re.compile(r"focus_count=(\d+)")
_FOCUS_TIME_RE = re.compile(r"total_focus_time_ms=(\d+)")
_SHA1_RE = re.compile(r"sha1=([0-9a-fA-F]+)")
_SIZE_RE = re.compile(r"size=(\d+)")
_SID_RE = re.compile(r"sid=([\w-]+)")


def _extract_path(description: str) -> str | None:
    match = _PATH_RE.search(description)
    return match.group(1) if match else None


def _basename(path: str) -> str:
    return path.replace("/", "\\").rsplit("\\", 1)[-1].lower()


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
        annotated.append(entry)
    return annotated


def _build_component_timeline(annotated_by_type: dict[str, list[dict]]) -> list[dict]:
    """Cross-hive correlation, keyed by basename: what does each of the three
    independent hive sources say about the SAME binary? UserAssist/ShimCache/Amcache are
    different OS subsystems recording different things (GUI launch, cache insertion,
    install) about what's very often the same file -- seeing them agree is stronger
    evidence than any one alone, and is the actual finding a flat per-hive dump misses.
    """
    components: dict[str, dict] = {}
    for artifact_type, findings in annotated_by_type.items():
        for finding in findings:
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
    return notes


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
            "confidence": CONFIDENCE_BY_TYPE.get(artifact_type, "unknown"),
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

    return {
        "details": details,
        "summary": details.get("summary", ""),
        "errors": details.get("errors", []),
        "hives_analyzed": [HIVE_LABELS[k] for k, provided in hives_provided.items() if provided],
        "hives_missing": [HIVE_LABELS[k] for k, provided in hives_provided.items() if not provided],
        "sections": sections,
        "total_findings": sum(len(s["findings"]) for s in sections),
        "component_timeline": component_timeline,
        "corroborated_components": sum(1 for c in component_timeline if len(c["seen_in"]) > 1),
        "linked_launches": linked_launches,
        "quiet_hive_notes": quiet_hive_notes,
        "profiles": profiles,
        "narrative": build_narrative(
            annotated_by_type,
            component_timeline,
            linked_launches,
            quiet_hive_notes,
            profiles,
            local_tz,
        ),
        "glossary": GLOSSARY,
    }
