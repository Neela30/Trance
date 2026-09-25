"""Scan <output-dir>/*/findings.json for the History tab -- no separate store, the
filesystem is the source of truth, same convention the rest of TRANCE uses. Framework-
agnostic (no Qt import), so it's unit-testable without a display.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

FINDINGS_FILENAME = "findings.json"
REPORT_FILENAME = "report.html"
CUSTODY_FILENAME = "custody.json"


@dataclass
class CaseSummary:
    case_name: str
    case_dir: Path
    findings_path: Path
    generated_at: str | None
    overall_status: str  # "ok" or "error", same derivation as main.PipelineResult.has_error
    module_statuses: dict[str, str]
    artifact_count: int
    report_path: Path | None
    custody_path: Path | None


def _summarize(case_dir: Path, findings_path: Path) -> CaseSummary | None:
    try:
        findings = json.loads(findings_path.read_text())
    except (OSError, json.JSONDecodeError):
        return None

    modules = findings.get("modules", {})
    module_statuses = {name: entry.get("status") for name, entry in modules.items()}
    overall_status = "error" if "error" in module_statuses.values() else "ok"
    artifact_count = sum(entry.get("artifact_count", 0) for entry in modules.values())

    report_path = case_dir / REPORT_FILENAME
    custody_path = case_dir / CUSTODY_FILENAME

    return CaseSummary(
        case_name=findings.get("case", {}).get("name", case_dir.name),
        case_dir=case_dir,
        findings_path=findings_path,
        generated_at=findings.get("generated_at"),
        overall_status=overall_status,
        module_statuses=module_statuses,
        artifact_count=artifact_count,
        report_path=report_path if report_path.is_file() else None,
        custody_path=custody_path if custody_path.is_file() else None,
    )


def scan_history(output_dir: Path) -> list[CaseSummary]:
    """Most-recent-first. A case directory without a readable findings.json (still
    running, or a crashed/partial run) is silently skipped, not reported as an error --
    it simply isn't a completed analysis yet."""
    if not output_dir.is_dir():
        return []

    summaries = []
    for case_dir in sorted(output_dir.iterdir()):
        if not case_dir.is_dir():
            continue
        findings_path = case_dir / FINDINGS_FILENAME
        if not findings_path.is_file():
            continue
        summary = _summarize(case_dir, findings_path)
        if summary is not None:
            summaries.append(summary)

    summaries.sort(key=lambda s: s.generated_at or "", reverse=True)
    return summaries
