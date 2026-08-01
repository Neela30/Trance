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
