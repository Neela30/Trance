"""Central configuration for TRANCE modules."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

# Case and examiner details printed on the report's first page and in the declaration
# (key, label, CLI flag). One list for the CLI, the GUI form and the report.
CASE_INFO_FIELDS = (
    ("examiner", "Examiner", "--examiner"),
    ("organisation", "Organisation", "--organisation"),
    ("reference", "Case / reference no.", "--reference"),
    ("requested_by", "Requested by", "--requested-by"),
    ("purpose", "Purpose and scope", "--purpose"),
    ("exhibit_prefix", "Exhibit prefix", "--exhibit-prefix"),
)


@dataclass
class TranceConfig:
    case_name: str
    output_dir: Path
    evidence_dir: Path | None = None
    verbose: bool = False
    # IANA zone name (e.g. "Asia/Colombo") the report's plain-English section shows local
    # times in, alongside UTC. None means auto-detect the analyst machine's own zone at
    # report-render time (see report.py:write_report) -- resolved that late, not here, so
    # a config built once and reused doesn't freeze in a stale "current machine" guess.
    report_timezone: str | None = None
    # CASE_INFO_FIELDS key -> value; blank fields are left out.
    case_info: dict[str, str] = field(default_factory=dict)
