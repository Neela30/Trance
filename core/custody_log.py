"""Chain-of-custody logging for acquired and processed evidence."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path


@dataclass
class CustodyEntry:
    artifact_path: str
    sha256: str
    action: str
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    notes: str = ""


class CustodyLog:
    def __init__(self, log_path: Path):
        self.log_path = log_path
        self.entries: list[CustodyEntry] = []

    def record(self, entry: CustodyEntry) -> None:
        self.entries.append(entry)

    def save(self) -> None:
        self.log_path.write_text(
            json.dumps([asdict(e) for e in self.entries], indent=2)
        )
