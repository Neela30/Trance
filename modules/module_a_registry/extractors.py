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
from regipy.plugins.ntuser.comdlg32 import ComDlg32Plugin
from regipy.plugins.ntuser.muicache import MUICachePlugin
from regipy.plugins.ntuser.recentdocs import RecentDocsPlugin
from regipy.plugins.ntuser.runmru import RunMRUPlugin
from regipy.plugins.ntuser.user_assist import UserAssistPlugin
from regipy.plugins.ntuser.word_wheel_query import WordWheelQueryPlugin
from regipy.plugins.software.installed_programs import InstalledProgramsSoftwarePlugin
from regipy.plugins.software.profilelist import ProfileListPlugin
from regipy.plugins.system.bam import BAMPlugin
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


def extract_bam(system_path: Path) -> list[dict]:
    """Extract Background Activity Moderator entries (per-SID last-execution timestamp
    per full exe path) from SYSTEM -- a corroborating execution-evidence subsystem
    independent of UserAssist/ShimCache/Amcache. Already flat, one record per execution
    record -- no flattening needed."""
    hive = _load_hive(system_path)
    plugin = BAMPlugin(hive, as_json=True)
    if not plugin.can_run():
        raise ParsingError(f"BAM plugin cannot run against {system_path}: not a SYSTEM hive.")
    try:
        plugin.run()
    except Exception as exc:
        raise ParsingError(f"BAM extraction failed for {system_path}: {exc}") from exc
    return plugin.entries


def extract_muicache(ntuser_path: Path) -> list[dict]:
    """Extract MUICache entries (display names of apps invoked via the shell) from
    NTUSER.DAT. MUICachePlugin groups results by registry key (one entry per hive path,
    each holding a list of applications) -- flattened here to one record per
    application, same shape as extract_recentdocs()'s flattening."""
    hive = _load_hive(ntuser_path)
    plugin = MUICachePlugin(hive, as_json=True)
    if not plugin.can_run():
        raise ParsingError(
            f"MUICache plugin cannot run against {ntuser_path}: not an NTUSER.DAT hive."
        )
    try:
        plugin.run()
    except Exception as exc:
        raise ParsingError(f"MUICache extraction failed for {ntuser_path}: {exc}") from exc

    flattened: list[dict] = []
    for key_entry in plugin.entries:
        for app in key_entry.get("applications", []):
            flattened.append(
                {
                    "key_path": key_entry.get("key_path"),
                    "last_write": key_entry.get("last_write"),
                    "path": app.get("path"),
                    "display_name": app.get("display_name"),
                    "filename": app.get("filename"),
                }
            )
    return flattened


def extract_runmru(ntuser_path: Path) -> list[dict]:
    """Extract Run dialog (Win+R) command history from NTUSER.DAT. RunMRUPlugin returns
    one record for the whole key (holding a list of commands) -- flattened here to one
    record per typed command, same shape as extract_recentdocs()'s flattening."""
    hive = _load_hive(ntuser_path)
    plugin = RunMRUPlugin(hive, as_json=True)
    if not plugin.can_run():
        raise ParsingError(
            f"RunMRU plugin cannot run against {ntuser_path}: not an NTUSER.DAT hive."
        )
    try:
        plugin.run()
    except Exception as exc:
        raise ParsingError(f"RunMRU extraction failed for {ntuser_path}: {exc}") from exc

    flattened: list[dict] = []
    for key_entry in plugin.entries:
        for item in key_entry.get("commands", []):
            flattened.append(
                {
                    "key_path": key_entry.get("key_path"),
                    "last_write": key_entry.get("last_write"),
                    "letter": item.get("letter"),
                    "command": item.get("command"),
                }
            )
    return flattened


def extract_word_wheel_query(ntuser_path: Path) -> list[dict]:
    """Extract Explorer/Start-menu search history (WordWheelQuery) from NTUSER.DAT.
    Already flat, one record per search entry -- no flattening needed."""
    hive = _load_hive(ntuser_path)
    plugin = WordWheelQueryPlugin(hive, as_json=True)
    if not plugin.can_run():
        raise ParsingError(
            f"WordWheelQuery plugin cannot run against {ntuser_path}: not an NTUSER.DAT hive."
        )
    try:
        plugin.run()
    except Exception as exc:
        raise ParsingError(f"WordWheelQuery extraction failed for {ntuser_path}: {exc}") from exc
    return plugin.entries


def extract_comdlg32(ntuser_path: Path) -> list[dict]:
    """Extract Open/Save dialog MRU paths from NTUSER.DAT. ComDlg32Plugin groups results
    by MRU-type/extension (one entry per key, each holding a list of items) --
    flattened here to one record per path, same shape as extract_recentdocs()'s
    flattening. Note: regipy's own PIDL-bytes parser here is best-effort (loose
    byte-scanning with swallowed exceptions) -- treat its output as lower-confidence
    than the other NTUSER extractors."""
    hive = _load_hive(ntuser_path)
    plugin = ComDlg32Plugin(hive, as_json=True)
    if not plugin.can_run():
        raise ParsingError(
            f"ComDlg32 plugin cannot run against {ntuser_path}: not an NTUSER.DAT hive."
        )
    try:
        plugin.run()
    except Exception as exc:
        raise ParsingError(f"ComDlg32 extraction failed for {ntuser_path}: {exc}") from exc

    flattened: list[dict] = []
    for key_entry in plugin.entries:
        for item in key_entry.get("items", []):
            flattened.append(
                {
                    "key_path": key_entry.get("key_path"),
                    "mru_type": key_entry.get("mru_type"),
                    "extension": key_entry.get("extension"),
                    "last_write": key_entry.get("last_write"),
                    "path": item.get("path"),
                }
            )
    return flattened


def extract_installed_programs(software_path: Path) -> list[dict]:
    """Extract the traditional Uninstall-key installed-programs list from SOFTWARE.
    Already flat, one record per installed program -- no flattening needed."""
    hive = _load_hive(software_path)
    plugin = InstalledProgramsSoftwarePlugin(hive, as_json=True)
    if not plugin.can_run():
        raise ParsingError(
            f"InstalledPrograms plugin cannot run against {software_path}: not a SOFTWARE hive."
        )
    try:
        plugin.run()
    except Exception as exc:
        raise ParsingError(
            f"InstalledPrograms extraction failed for {software_path}: {exc}"
        ) from exc
    return plugin.entries


def extract_profiles(software_path: Path) -> list[dict]:
    """Extract the ProfileList (SID -> username/profile-path/load-time) from SOFTWARE.
    Not Tor-relevance filtered -- this is reference data about every Windows account on
    the machine, used to resolve BAM's `sid` field and the narrative's user-account
    line, not a Tor-related finding in its own right. Already flat, one record per
    profile -- no flattening needed."""
    hive = _load_hive(software_path)
    plugin = ProfileListPlugin(hive, as_json=True)
    if not plugin.can_run():
        raise ParsingError(
            f"ProfileList plugin cannot run against {software_path}: not a SOFTWARE hive."
        )
    try:
        plugin.run()
    except Exception as exc:
        raise ParsingError(f"ProfileList extraction failed for {software_path}: {exc}") from exc
    return plugin.entries
