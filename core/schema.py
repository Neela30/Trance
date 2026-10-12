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
    # Structured counterparts to what used to be baked into `description` prose
    # (module_a_registry only, as of Phase 0 of its roadmap) -- optional/defaulted so
    # modules that never set them (B, C) are unaffected and findings.json stays additive.
    confidence: str | None = None  # "high" | "medium" | "low"
    confidence_reason: str | None = None  # one-line, examiner-facing justification
    category: str | None = None  # "tor-direct" | "context" (module_a_registry only)


MODULE_STATUSES = ("ok", "partial", "skipped", "not_implemented", "error")


@dataclass
class ModuleResult:
    """What every module's run() returns to main.py, and what findings.json is built from.

    status:   "ok" ran and produced artifacts/details with no failures; "partial" ran, and
              produced real artifacts/details, but one or more independent extraction
              steps failed (see details["warnings"]) -- distinct from "error", which is
              reserved for a failure that means nothing in this module's output can be
              trusted at all (e.g. a chain-of-custody integrity hash mismatch). A module
              with per-step isolation (Module A's per-artifact-type extractors, Module B's
              per-source analyses) should report "partial" rather than "error" when some
              steps succeed and others don't -- see root report.py's presenter gate, which
              treats "ok"/"partial" the same (both get the module's full presenter) and
              only "error" falls back to a generic table. "skipped": no evidence was
              supplied for it this run; "not_implemented": stub; "error": see message.
    details:  module-specific structured output kept verbatim under
              modules.<name>.details in findings.json, so a module can carry more than a
              flat artifact list (e.g. Module C's targeted/timeline/unfiltered sections).
              A module reporting "partial" should include a `details["warnings"]` list of
              `{"artifact_type", "source", "reason"}` (plus an optional "traceback" for
              log-level debugging) -- the shared shape root report.py's Module-status card
              renders for any module, not just Module A.
    message:  human-readable reason for a non-ok status, or None.
    duration_seconds: wall-clock time the module's run() took, set by main.run_module (None
              when a result was built any other way), so a slow stage can be found by
              reading findings.json instead of guessing.
    """

    module: str
    status: str
    artifacts: list[Artifact] = field(default_factory=list)
    details: dict = field(default_factory=dict)
    message: str | None = None
    duration_seconds: float | None = None
