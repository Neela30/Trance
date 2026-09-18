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

# Strongest evidence first: UserAssist/Amcache are HIGH confidence, ShimCache MEDIUM,
# RecentDocs LOW (contextual only) — see normalize.py's own docstring for the reasoning.
ARTIFACT_TYPE_ORDER = ("UserAssist", "Amcache", "ShimCache", "RecentDocs")
ARTIFACT_TYPE_LABELS = {
    "UserAssist": "UserAssist — GUI-launched execution",
    "Amcache": "Amcache — install / first-seen",
    "ShimCache": "ShimCache / AppCompatCache",
    "RecentDocs": "RecentDocs — contextual",
}
CONFIDENCE_BY_TYPE = {
    "UserAssist": "high",
    "Amcache": "high",
    "ShimCache": "medium",
    "RecentDocs": "low",
}
HIVE_LABELS = {
    "ntuser": "NTUSER.DAT",
    "system": "SYSTEM",
    "amcache": "Amcache.hve",
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
        return ARTIFACT_TYPE_ORDER.index(artifact_type) if artifact_type in ARTIFACT_TYPE_ORDER else 99

    timeline = []
    for component in components.values():
        sources = component["sources"]
        amcache_ts = [_parse_timestamp(f["timestamp"]) for f in sources.get("Amcache", [])]
        userassist_ts = [_parse_timestamp(f["timestamp"]) for f in sources.get("UserAssist", [])]
        timeline.append(
            {
                "basename": component["basename"],
                "paths": sorted(component["paths"]),
                "seen_in": sorted(sources.keys(), key=type_rank),
                "amcache_first_seen": min((t for t in amcache_ts if t), default=None),
                "userassist_run_count": sum(f.get("run_count") or 0 for f in sources.get("UserAssist", [])),
                "userassist_last_run": max((t for t in userassist_ts if t), default=None),
                "shimcache_hits": len(sources.get("ShimCache", [])),
            }
        )
    # Strongest evidence first: more independent sources agreeing > fewer; ties broken by name.
    timeline.sort(key=lambda c: (-len(c["seen_in"]), c["basename"]))
    return timeline


def build_context(details: dict) -> dict:
    """Presentation context for the registry section of the case report."""
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
    }
