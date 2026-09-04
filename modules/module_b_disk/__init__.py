"""Module B — disk & database artifacts. Not implemented yet.

Contract (see README, "Module contract"): run(config, **kwargs) -> ModuleResult.
Return status "ok" with a list of core.schema.Artifact once real parsing exists.
"""

from __future__ import annotations

from core.config import TranceConfig
from core.schema import ModuleResult

MODULE_NAME = "module_b_disk"


def run(config: TranceConfig, **_: object) -> ModuleResult:
    return ModuleResult(module=MODULE_NAME, status="not_implemented", message="disk/database parsing not written yet")
