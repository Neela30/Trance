"""Module A's contribution to the case report: turn registry findings into presentation context.

Mirrors modules/module_c_memory/report.py's split: this renders nothing itself (root-level
report.py owns the template and the HTML); it only prepares module_a's view of `details`
(what __init__.py's run() adapter put there) for the template. Confidence levels/ordering
here just restate what normalize.py already decided per artifact type (2.4 of the project
brief) — this is presentation grouping, not a second interpretation of the evidence.
"""

from __future__ import annotations

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


def build_context(details: dict) -> dict:
    """Presentation context for the registry section of the case report."""
    findings_by_type = details.get("findings_by_type", {})
    sections = [
        {
            "type": artifact_type,
            "label": ARTIFACT_TYPE_LABELS.get(artifact_type, artifact_type),
            "confidence": CONFIDENCE_BY_TYPE.get(artifact_type, "unknown"),
            "findings": findings_by_type[artifact_type],
        }
        for artifact_type in ARTIFACT_TYPE_ORDER
        if findings_by_type.get(artifact_type)
    ]
    hives_provided = details.get("hives_provided", {})
    return {
        "details": details,
        "summary": details.get("summary", ""),
        "errors": details.get("errors", []),
        "hives_analyzed": [HIVE_LABELS[k] for k, provided in hives_provided.items() if provided],
        "hives_missing": [HIVE_LABELS[k] for k, provided in hives_provided.items() if not provided],
        "sections": sections,
        "total_findings": sum(len(s["findings"]) for s in sections),
    }
