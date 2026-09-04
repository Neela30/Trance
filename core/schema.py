"""Shared data schemas for artifacts reported across modules."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class Artifact:
    module: str
    artifact_type: str
    source: str
    description: str
    sha256: str | None = None
    timestamp: str | None = None


MODULE_STATUSES = ("ok", "skipped", "not_implemented", "error")


@dataclass
class ModuleResult:
    """What every module's run() returns to main.py, and what findings.json is built from.

    status:   "ok" ran and produced artifacts/details; "skipped" no evidence was supplied
              for it this run; "not_implemented" stub; "error" raised — see message.
    details:  module-specific structured output kept verbatim under
              modules.<name>.details in findings.json, so a module can carry more than a
              flat artifact list (e.g. Module C's targeted/timeline/unfiltered sections).
    message:  human-readable reason for a non-ok status, or None.
    """

    module: str
    status: str
    artifacts: list[Artifact] = field(default_factory=list)
    details: dict = field(default_factory=dict)
    message: str | None = None
