"""Thin, pure wrappers around regipy plugins for each Module A artifact.

Each function here does exactly one thing: open a hive read-only, run one
regipy plugin against it, and return its raw `entries` list. Deliberately
kept free of hashing and chain-of-custody concerns — those belong to the
shared acquisition layer / pipeline.py, so these functions stay trivially
unit-testable (with mocks) and reusable outside the pipeline (e.g. from a
notebook or an ad-hoc script) without dragging in custody-logging
side effects.

Every function raises core.exceptions.ParsingError on failure — either
because the plugin refuses to run against the given hive (wrong hive type,
per regipy's own `can_run()` check) or because regipy itself throws while
parsing a malformed/corrupted hive. Callers (the pipeline) decide whether a
ParsingError for one artifact should abort the whole run or just be noted
and skipped — see pipeline.py's per-hive handling.
"""

from __future__ import annotations

from pathlib import Path

from regipy.plugins.amcache.amcache import AmCachePlugin
from regipy.plugins.ntuser.recentdocs import RecentDocsPlugin
from regipy.plugins.ntuser.user_assist import UserAssistPlugin
from regipy.plugins.system.shimcache import ShimCachePlugin
from regipy.registry import RegistryHive

from core.exceptions import ParsingError


def _load_hive(hive_path: Path) -> RegistryHive:
    try:
        return RegistryHive(str(hive_path))
    except Exception as exc:  # regipy raises its own exception hierarchy
        raise ParsingError(f"Could not open registry hive at {hive_path}: {exc}") from exc


def extract_user_assist(ntuser_path: Path) -> list[dict]:
    """Extract UserAssist entries (run count, last-executed time) from NTUSER.DAT."""
    hive = _load_hive(ntuser_path)
    plugin = UserAssistPlugin(hive, as_json=True)
    if not plugin.can_run():
        raise ParsingError(
            f"UserAssist plugin cannot run against {ntuser_path}: "
            f"not recognized as an NTUSER.DAT hive."
        )
    try:
        plugin.run()
    except Exception as exc:
        raise ParsingError(f"UserAssist extraction failed for {ntuser_path}: {exc}") from exc
    return plugin.entries


def extract_shimcache(system_path: Path) -> list[dict]:
    """Extract ShimCache/AppCompatCache entries from SYSTEM.

    Note: ShimCache reflects insertion order into the cache, not confirmed
    execution — this caveat is preserved as a confidence annotation in
    normalize.py, not silently dropped here.
    """
    hive = _load_hive(system_path)
    plugin = ShimCachePlugin(hive, as_json=True)
    if not plugin.can_run():
        raise ParsingError(
            f"ShimCache plugin cannot run against {system_path}: "
            f"not recognized as a SYSTEM hive."
        )
    try:
        plugin.run()
    except Exception as exc:
        raise ParsingError(f"ShimCache extraction failed for {system_path}: {exc}") from exc
    return plugin.entries


def extract_amcache(amcache_path: Path) -> list[dict]:
    """Extract Amcache entries (install path, first-seen time, SHA-1) from Amcache.hve."""
    hive = _load_hive(amcache_path)
    plugin = AmCachePlugin(hive, as_json=True)
    if not plugin.can_run():
        raise ParsingError(
            f"Amcache plugin cannot run against {amcache_path}: "
            f"not recognized as an Amcache.hve hive."
        )
    try:
        plugin.run()
    except Exception as exc:
        raise ParsingError(f"Amcache extraction failed for {amcache_path}: {exc}") from exc
    return plugin.entries


def extract_recentdocs(ntuser_path: Path) -> list[dict]:
    """Extract RecentDocs entries from NTUSER.DAT, flattened to one dict per document.

    RecentDocsPlugin groups results by registry key (one entry per
    extension subkey, each holding a list of documents). That shape is
    awkward for uniform Tor-relevance filtering, so this flattens it to one
    record per document — the same "list of flat dicts" shape the other
    three extractors already return — before it ever reaches the pipeline.
    """
    hive = _load_hive(ntuser_path)
    plugin = RecentDocsPlugin(hive, as_json=True)
    if not plugin.can_run():
        raise ParsingError(
            f"RecentDocs plugin cannot run against {ntuser_path}: "
            f"not recognized as an NTUSER.DAT hive."
        )
    try:
        plugin.run()
    except Exception as exc:
        raise ParsingError(f"RecentDocs extraction failed for {ntuser_path}: {exc}") from exc

    flattened: list[dict] = []
    for key_entry in plugin.entries:
        for document in key_entry.get("documents", []):
            flattened.append(
                {
                    "key_path": key_entry.get("key_path"),
                    "extension": key_entry.get("extension"),
                    "last_write": key_entry.get("last_write"),
                    "index": document.get("index"),
                    "name": document.get("name"),
                }
            )
    return flattened
