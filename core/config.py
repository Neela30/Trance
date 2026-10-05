"""Central configuration for TRANCE modules."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


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
