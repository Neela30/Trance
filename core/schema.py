"""Shared data schemas for artifacts reported across modules."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class Artifact:
    module: str
    artifact_type: str
    source: str
    description: str
    sha256: str | None = None
    timestamp: str | None = None
