"""Merge every module's ModuleResult into the single findings.json TRANCE emits per case.

Shape:
    {
      "schema_version": 1,
      "case": {"name", "output_dir", "evidence_dir"},
      "generated_at": "<UTC ISO-8601>",
      "modules": {
        "<module>": {"status", "message", "artifact_count", "details": {...module-specific...}}
      },
      "artifacts": [ ...every core.schema.Artifact from every module, flattened... ]
    }

`artifacts` is the cross-module, uniform list (each entry carries its `module`), so
correlation across registry/disk/memory can work off one array. `details` keeps each
module's richer structured output verbatim for the report and for re-analysis.
"""

from __future__ import annotations

import json
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path

from core.config import TranceConfig
from core.schema import ModuleResult

FINDINGS_FILENAME = "findings.json"
SCHEMA_VERSION = 1


def build_findings(config: TranceConfig, results: list[ModuleResult]) -> dict:
    return {
        "schema_version": SCHEMA_VERSION,
        "case": {
            "name": config.case_name,
            "output_dir": str(config.output_dir),
            "evidence_dir": str(config.evidence_dir) if config.evidence_dir else None,
        },
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "modules": {
            r.module: {
                "status": r.status,
                "message": r.message,
                "artifact_count": len(r.artifacts),
                "details": r.details,
            }
            for r in results
        },
        "artifacts": [asdict(a) for r in results for a in r.artifacts],
    }


def write_findings(findings: dict, output_dir: Path) -> Path:
    output_dir.mkdir(parents=True, exist_ok=True)
    path = output_dir / FINDINGS_FILENAME
    path.write_text(json.dumps(findings, indent=2))
    return path


def load_findings(path: Path) -> dict:
    return json.loads(path.read_text())
