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

One exception to "wraps a plugin": extract_last_visited_pidl_mru() reuses regipy's own
public parse_pidl_mru_value() utility and LAST_VISITED_PIDL_MRU_PATH constant directly,
bypassing ComDlg32Plugin's own LastVisitedPidlMRU method — see that function's docstring
for why (that one method is structurally wrong for this specific MRU and returns nothing
against a real hive; its sibling OpenSavePidlMRU/OpenSaveMRU handling is unaffected and
still used as-is via extract_comdlg32()).
"""

from __future__ import annotations

import logging
from pathlib import Path

from regipy.exceptions import RegistryKeyNotFoundException
from regipy.plugins.amcache.amcache import AmCachePlugin
from regipy.plugins.ntuser.comdlg32 import (
    LAST_VISITED_PIDL_MRU_PATH,
    ComDlg32Plugin,
    parse_pidl_mru_value,
)
from regipy.plugins.ntuser.muicache import MUICachePlugin
from regipy.plugins.ntuser.recentdocs import RecentDocsPlugin
from regipy.plugins.ntuser.runmru import RunMRUPlugin
from regipy.plugins.ntuser.typed_paths import TypedPathsPlugin
from regipy.plugins.ntuser.user_assist import UserAssistPlugin
from regipy.plugins.ntuser.word_wheel_query import WordWheelQueryPlugin
from regipy.plugins.software.installed_programs import InstalledProgramsSoftwarePlugin
from regipy.plugins.software.networklist import (
    CATEGORY_TYPES,
    NAME_TYPES,
    PROFILES_PATH,
    SIGNATURES_PATH,
    format_mac_address,
    parse_network_date,
)
from regipy.plugins.software.profilelist import ProfileListPlugin
from regipy.plugins.software.winver import WinVersionPlugin
from regipy.plugins.system.bam import BAMPlugin
from regipy.plugins.system.computer_name import ComputerNamePlugin
from regipy.plugins.system.mountdev import MOUNTED_DEVICES_PATH, parse_device_data
from regipy.plugins.system.network_data import NetworkDataPlugin
from regipy.plugins.system.shimcache import ShimCachePlugin
from regipy.plugins.system.timezone_data2 import TimezoneDataPlugin2
from regipy.plugins.system.usb_devices import USBDevicesPlugin
from regipy.plugins.system.usbstor import USBSTORPlugin
from regipy.plugins.usrclass.shellbags_usrclass import ShellBagUsrclassPlugin
from regipy.registry import RegistryHive
from regipy.utils import convert_wintime

from core.exceptions import ParsingError

from ._muicache_grouping import group_muicache_values
from ._shellbags_patch import apply_shellbags_patch

logger = logging.getLogger(__name__)


def _load_hive(hive_path: Path, hive_type: str) -> RegistryHive:
    """Always opens with an EXPLICIT hive_type rather than relying on regipy's own
    identify_hive_type() auto-detection, which reads the *embedded* path string from the
    hive file's own header (not the filesystem filename passed here) -- and for at least
    "usrclass", that check is an exact string-equality against a bare, driveless path
    (r"\\microsoft\\windows\\usrclass.dat") that a real acquired hive's embedded header
    (a full path like "\\??\\C:\\Users\\<user>\\AppData\\Local\\Microsoft\\Windows\\
    UsrClass.dat") will never match -- auto-detection would silently leave hive_type=None
    and every plugin's can_run() would then reject a hive that is, in fact, exactly the
    right type. Explicit hive_type is regipy's own documented escape hatch for this,
    verified against the installed regipy (6.3.0) RegistryHive.__init__ docstring."""
    try:
        return RegistryHive(str(hive_path), hive_type=hive_type)
    except Exception as exc:  # regipy raises its own exception hierarchy
        raise ParsingError(f"Could not open registry hive at {hive_path}: {exc}") from exc


def extract_user_assist(ntuser_path: Path) -> list[dict]:
    """Extract UserAssist entries (run count, last-executed time) from NTUSER.DAT."""
    hive = _load_hive(ntuser_path, "ntuser")
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
    hive = _load_hive(system_path, "system")
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
    hive = _load_hive(amcache_path, "amcache")
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
    hive = _load_hive(ntuser_path, "ntuser")
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
    hive = _load_hive(system_path, "system")
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
    each holding a list of applications) -- flattened here to one record per raw
    registry value, then grouped by group_muicache_values() to merge the Vista+
    FriendlyAppName/ApplicationCompany value pair for the same program into one finding
    (see that module's docstring for the confirmed real-world bug this fixes)."""
    hive = _load_hive(ntuser_path, "ntuser")
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
    return group_muicache_values(flattened)
    return flattened


def extract_runmru(ntuser_path: Path) -> list[dict]:
    """Extract Run dialog (Win+R) command history from NTUSER.DAT. RunMRUPlugin returns
    one record for the whole key (holding a list of commands) -- flattened here to one
    record per typed command, same shape as extract_recentdocs()'s flattening."""
    hive = _load_hive(ntuser_path, "ntuser")
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
    hive = _load_hive(ntuser_path, "ntuser")
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
    hive = _load_hive(ntuser_path, "ntuser")
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
    hive = _load_hive(software_path, "software")
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
    hive = _load_hive(software_path, "software")
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


# ---------------------------------------------------------------------------
# Context facts (Phase 0 of the Module A roadmap) -- reinstated as thin regipy-plugin
# wrappers. These were originally hand-written against the raw RegistryHive/NKRecord API
# in a since-removed system_context.py, before a fuller audit of regipy's own plugin set
# turned up ComputerNamePlugin/TimezoneDataPlugin2/WinVersionPlugin -- real plugins for
# exactly these three facts, missed the first time around. Per this project's "use
# existing regipy plugins where they exist" rule, they replace the custom versions here.
# ---------------------------------------------------------------------------


def extract_computer_name(system_path: Path) -> list[dict]:
    """Computer name from SYSTEM. ComputerNamePlugin emits one entry per ControlSet
    get_control_sets() finds (usually one, occasionally two near-identical ones on a
    system with a stale ControlSet002) -- not narrowed to "the active" one; report.py's
    existing _dedupe() already collapses byte-identical duplicates downstream."""
    hive = _load_hive(system_path, "system")
    plugin = ComputerNamePlugin(hive, as_json=True)
    if not plugin.can_run():
        raise ParsingError(
            f"ComputerName plugin cannot run against {system_path}: not a SYSTEM hive."
        )
    try:
        plugin.run()
    except Exception as exc:
        raise ParsingError(f"ComputerName extraction failed for {system_path}: {exc}") from exc
    return plugin.entries


def extract_time_zone(system_path: Path) -> list[dict]:
    """Windows' configured time zone from SYSTEM. TimezoneDataPlugin2 (not v1) is used
    deliberately -- it sign-corrects Bias/DaylightBias/ActiveTimeBias and decodes
    TimeZoneKeyName from UTF-16, where v1 hands back raw, unsigned, undecoded values.
    plugin.entries is a dict keyed by control-set path, not a list -- flattened here to
    the same "list of flat dicts" shape every other extractor in this file returns."""
    hive = _load_hive(system_path, "system")
    plugin = TimezoneDataPlugin2(hive, as_json=True)
    if not plugin.can_run():
        raise ParsingError(
            f"TimezoneData plugin cannot run against {system_path}: not a SYSTEM hive."
        )
    try:
        plugin.run()
    except Exception as exc:
        raise ParsingError(f"TimezoneData extraction failed for {system_path}: {exc}") from exc

    flattened: list[dict] = []
    for key_path, values in plugin.entries.items():
        flattened.append({**values, "key_path": key_path})
    return flattened


def extract_windows_version(software_path: Path) -> list[dict]:
    """Windows edition/build from SOFTWARE's Microsoft\\Windows NT\\CurrentVersion.
    plugin.entries is a single-key dict (one path -> one dict of values) -- flattened
    here the same way extract_time_zone() flattens its own dict-of-dicts shape."""
    hive = _load_hive(software_path, "software")
    plugin = WinVersionPlugin(hive, as_json=True)
    if not plugin.can_run():
        raise ParsingError(
            f"WinVersion plugin cannot run against {software_path}: not a SOFTWARE hive."
        )
    try:
        plugin.run()
    except Exception as exc:
        raise ParsingError(f"WinVersion extraction failed for {software_path}: {exc}") from exc

    flattened: list[dict] = []
    for key_path, values in plugin.entries.items():
        flattened.append({**values, "key_path": key_path})
    return flattened


# ---------------------------------------------------------------------------
# Phase 1 of the Module A roadmap -- execution evidence.
# ---------------------------------------------------------------------------


def extract_shellbags(usrclass_path: Path) -> list[dict]:
    """Shell Bags (folder-browsing history) from UsrClass.dat -- the active location on
    Windows Vista+ (NTUSER.DAT's own ShellBags, via a sibling ShellBagNtuserPlugin, are
    the legacy pre-Vista location and are not wired up here; UsrClass.dat is what the
    Module A roadmap's Phase 1 asks for). Requires the `regipy[full]` extra
    (libfwsi-python/libfwps-python, importable as pyfwsi/pyfwps) -- ShellBagUsrclassPlugin
    raises ModuleNotFoundError itself with an actionable message if that's missing; left
    uncaught here rather than folded into ParsingError, since "dependency not installed"
    is a setup problem, not a parsing-time one.

    apply_shellbags_patch() (idempotent) fixes a confirmed pyfwsi bug -- see
    _shellbags_patch.py's module docstring for the full root-cause writeup -- where
    extension_block.get_creation_time() raises SystemError (not the OSError regipy's own
    plugin already guards against) on certain real-world entries, aborting the entire
    traversal instead of just the one bad item. With the patch applied, a slot regipy
    still can't read for some other reason is skipped individually (logged, counted on
    plugin._shellbags_skip_count) rather than losing every already-walked entry.
    """
    apply_shellbags_patch()
    hive = _load_hive(usrclass_path, "usrclass")
    plugin = ShellBagUsrclassPlugin(hive, as_json=True)
    if not plugin.can_run():
        raise ParsingError(
            f"ShellBags plugin cannot run against {usrclass_path}: not a UsrClass.dat hive."
        )
    plugin._shellbags_skip_count = 0
    plugin._shellbags_timestamp_failures = 0
    try:
        plugin.run()
    except Exception as exc:
        raise ParsingError(f"ShellBags extraction failed for {usrclass_path}: {exc}") from exc
    if plugin._shellbags_skip_count:
        logger.warning(
            f"ShellBags ({usrclass_path}): skipped {plugin._shellbags_skip_count} "
            "unreadable slot(s); all other entries extracted normally."
        )
    if plugin._shellbags_timestamp_failures:
        logger.info(
            f"ShellBags ({usrclass_path}): {plugin._shellbags_timestamp_failures}/"
            f"{len(plugin.entries)} entries had an unreadable creation/access/"
            "modification time (a confirmed pyfwsi library bug -- see "
            "_shellbags_patch.py); path and other metadata are unaffected."
        )
    return plugin.entries


def extract_typed_paths(ntuser_path: Path) -> list[dict]:
    """Paths typed into Explorer's address bar (TypedPaths) from NTUSER.DAT.
    TypedPathsPlugin.entries is {"last_write":, "entries": [{"url1": "..."}, ...]} -- a
    single dict, not a list -- flattened here to one record per typed path, same pattern
    as extract_recentdocs()'s flattening."""
    hive = _load_hive(ntuser_path, "ntuser")
    plugin = TypedPathsPlugin(hive, as_json=True)
    if not plugin.can_run():
        raise ParsingError(
            f"TypedPaths plugin cannot run against {ntuser_path}: not an NTUSER.DAT hive."
        )
    try:
        plugin.run()
    except Exception as exc:
        raise ParsingError(f"TypedPaths extraction failed for {ntuser_path}: {exc}") from exc

    last_write = plugin.entries.get("last_write") if plugin.entries else None
    flattened: list[dict] = []
    for item in (plugin.entries or {}).get("entries", []):
        for path in item.values():
            flattened.append({"path": path, "last_write": last_write})
    return flattened


def extract_last_visited_pidl_mru(ntuser_path: Path) -> list[dict]:
    """LastVisitedPidlMRU (program -> last-browsed-folder pairs) from NTUSER.DAT's
    ComDlg32 key -- NOT via ComDlg32Plugin._parse_last_visited_mru(), which is
    structurally wrong for this specific MRU: it reuses OpenSavePidlMRU/OpenSaveMRU's
    "value names are digit-indexed MRU slots" assumption, but LastVisitedPidlMRU's real
    values are named for the *invoking program's full path* (e.g.
    "E:\\Tor Browser\\Browser\\firefox.exe"), with no digit-named values at all -- so
    that method's `mru_values` stays empty and it silently returns zero entries against
    a real hive. This reimplements just that one pairing correctly, reusing
    LAST_VISITED_PIDL_MRU_PATH and parse_pidl_mru_value() -- both already-public regipy
    names from regipy.plugins.ntuser.comdlg32, not duplicating ComDlg32Plugin's own
    (working) OpenSavePidlMRU/OpenSaveMRU handling.

    The returned "program" field is a full executable path, so the existing
    is_tor_related() substring markers already apply to it unchanged -- see
    constants.is_tor_related_entry(), which checks this field for this artifact type.
    """
    hive = _load_hive(ntuser_path, "ntuser")
    try:
        key = hive.get_key(LAST_VISITED_PIDL_MRU_PATH)
    except RegistryKeyNotFoundException:
        return []
    except Exception as exc:
        raise ParsingError(
            f"LastVisitedPidlMRU extraction failed for {ntuser_path}: {exc}"
        ) from exc

    last_write = convert_wintime(key.header.last_modified, as_json=True)
    flattened: list[dict] = []
    for value in key.iter_values(trim_values=False):
        if value.name == "MRUListEx":
            continue
        folder = parse_pidl_mru_value(value.value)
        if not folder:
            continue
        flattened.append(
            {
                "key_path": LAST_VISITED_PIDL_MRU_PATH,
                "program": value.name,
                "path": folder,
                "last_write": last_write,
            }
        )
    return flattened


# ---------------------------------------------------------------------------
# Phase 2 of the Module A roadmap -- device evidence.
# ---------------------------------------------------------------------------


def extract_usbstor(system_path: Path) -> list[dict]:
    """USB mass-storage connection history from SYSTEM's Enum\\USBSTOR. Already flat,
    one record per device+serial -- no flattening needed. `serial_number` is the field
    report.py's device correlation (_build_device_correlation()) joins against
    MountedDevices' decoded device path."""
    hive = _load_hive(system_path, "system")
    plugin = USBSTORPlugin(hive, as_json=True)
    if not plugin.can_run():
        raise ParsingError(f"USBSTOR plugin cannot run against {system_path}: not a SYSTEM hive.")
    try:
        plugin.run()
    except Exception as exc:
        raise ParsingError(f"USBSTOR extraction failed for {system_path}: {exc}") from exc
    return plugin.entries


def extract_usb_devices(system_path: Path) -> list[dict]:
    """Generic USB device connection history (incl. non-storage, e.g. keyboards/mice)
    from SYSTEM's Enum\\USB -- complements extract_usbstor(), which only covers USB mass
    storage. Already flat, no flattening needed."""
    hive = _load_hive(system_path, "system")
    plugin = USBDevicesPlugin(hive, as_json=True)
    if not plugin.can_run():
        raise ParsingError(
            f"USB devices plugin cannot run against {system_path}: not a SYSTEM hive."
        )
    try:
        plugin.run()
    except Exception as exc:
        raise ParsingError(f"USB devices extraction failed for {system_path}: {exc}") from exc
    return plugin.entries


# Windows Dynamic Disk (Logical Disk Manager) volumes store "DMIO:ID:" + a 16-byte LDM
# object id as their MountedDevices value, instead of a path/signature/GUID -- confirmed
# against a real acquisition, not guessed (see extract_mounted_devices()'s own docstring).
# Windows does not support converting a removable USB disk to a dynamic disk, so this
# prefix is itself real, structural evidence a drive is a fixed/internal-disk partition,
# not a USB stick -- report.py's device correlation treats it as a distinct case from a
# genuinely undecodable value.
_DYNAMIC_DISK_PREFIX = b"DMIO:ID:"


def extract_mounted_devices(system_path: Path) -> list[dict]:
    """Drive-letter/volume-to-device mapping from SYSTEM's MountedDevices -- the key
    enabler for mapping the Tor install's drive letter to a physical device directly
    (report.py's _build_device_correlation()): each entry's own `mount_type` ("drive_letter"
    vs "volume") and, for a USB-attached drive, a decoded `path` field containing the
    same `_??_USBSTOR#...#<serial>#{GUID}` shape extract_usbstor()'s own `serial_number`
    is derived from -- the two are joined on that serial number, a real structural
    correlation rather than constants.infer_drive_letters()'s same-evidence path-suffix
    guess (kept unchanged -- a different problem: \\Device\\HarddiskVolumeN\\... -> letter).

    Deliberately does NOT use regipy's own MountedDevicesPlugin, despite one existing: its
    `run()` calls `iter_values()` with the default `trim_values=True`, which for
    REG_BINARY data (exactly what every MountedDevices value is) returns a HEX STRING, not
    `bytes` -- confirmed by reading regipy's own `NKRecord.iter_values()` source. Its own
    `isinstance(data, bytes)` check is therefore always False, so its `parse_device_data()`
    call is never reached and every entry decodes to nothing, regardless of what the value
    actually contains -- confirmed against a real SYSTEM hive (manually re-reading the same
    values with `trim_values=False` decodes them immediately). This reimplements the
    plugin's own short categorization logic (name prefix -> mount_type) directly, reusing
    regipy's own public `parse_device_data()` utility on real bytes -- same "bypass one
    broken piece, reuse the rest of the public API" precedent as
    extract_last_visited_pidl_mru()'s own docstring describes for a different plugin."""
    hive = _load_hive(system_path, "system")
    if hive.hive_type != "system":
        raise ParsingError(
            f"MountedDevices extraction cannot run against {system_path}: not a SYSTEM hive."
        )
    try:
        mounted_key = hive.get_key(MOUNTED_DEVICES_PATH)
    except RegistryKeyNotFoundException:
        return []
    except Exception as exc:
        raise ParsingError(f"MountedDevices extraction failed for {system_path}: {exc}") from exc

    last_write = convert_wintime(mounted_key.header.last_modified, as_json=True)
    entries: list[dict] = []
    try:
        values = list(mounted_key.iter_values(trim_values=False))
    except Exception as exc:
        raise ParsingError(f"MountedDevices extraction failed for {system_path}: {exc}") from exc

    for value in values:
        name = value.name
        data = value.value

        entry: dict = {
            "key_path": MOUNTED_DEVICES_PATH,
            "last_write": last_write,
            "value_name": name,
        }
        if name.startswith("\\DosDevices\\"):
            entry["mount_point"] = name.replace("\\DosDevices\\", "")
            entry["mount_type"] = "drive_letter"
        elif name.startswith("\\??\\Volume"):
            entry["mount_point"] = name
            entry["mount_type"] = "volume"
        elif name == "#{":
            entry["mount_type"] = "database"
        else:
            entry["mount_type"] = "other"

        if isinstance(data, bytes):
            if data.startswith(_DYNAMIC_DISK_PREFIX):
                entry["dynamic_disk"] = True
            else:
                entry.update(parse_device_data(data))
            entry["data_size"] = len(data)

        entries.append(entry)
    return entries


# ---------------------------------------------------------------------------
# Phase 3 of the Module A roadmap -- network context.
# ---------------------------------------------------------------------------


def _format_gateway_mac(value: object) -> str | None:
    mac = format_mac_address(value) if isinstance(value, bytes) else None
    return mac if isinstance(mac, str) else None


def extract_network_profiles(software_path: Path) -> list[dict]:
    """Network connection history (NetworkList\\Profiles joined with
    NetworkList\\Signatures\\{Managed,Unmanaged}) from SOFTWARE -- NOT via regipy's own
    NetworkListPlugin, despite one existing: its run() reads every value through
    extract_values()'s default iter_values() (trim_values=True), which for REG_BINARY data
    (exactly what DateCreated/DateLastConnected/DefaultGatewayMac are) returns a HEX
    STRING, not bytes -- the same confirmed regipy bug class already found and bypassed
    for MountedDevicesPlugin (see extract_mounted_devices()'s own docstring). Confirmed
    against a real SOFTWARE hive: running NetworkListPlugin as-is returns
    date_created=None/date_last_connected=None for every one of 59 real profiles, and a
    raw hex string (e.g. "e47deb7a4551") instead of a formatted MAC for
    default_gateway_mac. This reimplements the same two key paths directly, reusing that
    plugin's own public parse_network_date()/format_mac_address()/CATEGORY_TYPES/
    NAME_TYPES against real bytes read via iter_values(trim_values=False) -- same
    "bypass the one broken piece, reuse the rest of the public API" precedent as
    extract_mounted_devices()'s own docstring describes.

    DateCreated/DateLastConnected are decoded to a NAIVE local-time ISO string (no tzinfo)
    -- this is SYSTEMTIME in the machine's own local time, not UTC (confirmed by manually
    decoding a real value and cross-checking against the acquisition's own known local
    date); report.py/narrative.py are responsible for converting to UTC using the
    system's own recorded time zone bias (Phase 0's TimeZone fact) before ever comparing
    this against another (UTC) timestamp.

    Returns one flat dict per profile, joined with its Unmanaged/Managed signature (if
    any) on ProfileGuid -- a profile with no matching signature, or a signature with no
    matching profile, is still returned (never silently dropped) with the other half's
    fields left at their default (None / "unknown-guid").
    """
    hive = _load_hive(software_path, "software")

    profiles: dict[str, dict] = {}
    try:
        profiles_key = hive.get_key(PROFILES_PATH)
    except RegistryKeyNotFoundException:
        profiles_key = None
    except Exception as exc:
        raise ParsingError(
            f"NetworkList Profiles extraction failed for {software_path}: {exc}"
        ) from exc

    if profiles_key is not None:
        for subkey in profiles_key.iter_subkeys():
            entry: dict = {
                "profile_guid": subkey.name,
                "last_write": convert_wintime(subkey.header.last_modified, as_json=True),
            }
            for value in subkey.iter_values(trim_values=False):
                if value.name == "ProfileName":
                    entry["profile_name"] = value.value
                elif value.name == "Description":
                    entry["description"] = value.value
                elif value.name == "NameType" and isinstance(value.value, int):
                    entry["name_type"] = NAME_TYPES.get(value.value, f"Unknown ({value.value})")
                elif value.name == "Category" and isinstance(value.value, int):
                    entry["category"] = CATEGORY_TYPES.get(value.value, f"Unknown ({value.value})")
                elif value.name == "DateCreated" and isinstance(value.value, bytes):
                    entry["date_created_local"] = parse_network_date(value.value)
                elif value.name == "DateLastConnected" and isinstance(value.value, bytes):
                    entry["date_last_connected_local"] = parse_network_date(value.value)
            profiles[subkey.name] = entry

    signatures_by_guid: dict[str, dict] = {}
    for sig_type, sig_label in (("Managed", "managed"), ("Unmanaged", "unmanaged")):
        try:
            sig_key = hive.get_key(f"{SIGNATURES_PATH}\\{sig_type}")
        except RegistryKeyNotFoundException:
            continue
        except Exception as exc:
            raise ParsingError(
                f"NetworkList Signatures ({sig_type}) extraction failed for {software_path}: {exc}"
            ) from exc

        for subkey in sig_key.iter_subkeys():
            sig_entry: dict = {"signature_type": sig_label}
            profile_guid = None
            for value in subkey.iter_values(trim_values=False):
                if value.name == "ProfileGuid":
                    profile_guid = value.value
                elif value.name == "DefaultGatewayMac":
                    sig_entry["default_gateway_mac"] = _format_gateway_mac(value.value)
                elif value.name == "DnsSuffix":
                    sig_entry["dns_suffix"] = value.value
                elif value.name == "FirstNetwork":
                    sig_entry["first_network"] = value.value
            if profile_guid:
                # First signature wins for a given profile -- a profile practically never
                # has more than one Managed+Unmanaged signature in practice; deterministic
                # either way since iter_subkeys() order is stable.
                signatures_by_guid.setdefault(profile_guid, sig_entry)

    flattened: list[dict] = []
    for guid in sorted(set(profiles) | set(signatures_by_guid)):
        flattened.append(
            {**profiles.get(guid, {"profile_guid": guid}), **signatures_by_guid.get(guid, {})}
        )
    return flattened


def extract_network_interfaces(system_path: Path) -> list[dict]:
    """Per-interface IP/DHCP/gateway/DNS configuration from SYSTEM's
    Services\\Tcpip\\Parameters\\Interfaces, via regipy's own NetworkDataPlugin -- unlike
    NetworkListPlugin above, this one works correctly against a real hive (DHCP lease
    times are Unix-epoch DWORDs, not FILETIME, and the plugin converts them correctly;
    confirmed against a real SYSTEM hive with live DHCP lease data).

    Flattened to one dict per top-level interface, resolved per existing ControlSet (same
    "every ControlSet, not just the active one" approach as extractors.py's
    ComputerNamePlugin/TimezoneDataPlugin2 wrappers). Deliberately drops the plugin's own
    recursive "sub_interface" field: on a real hive this recursion walked into leftover
    WLAN-profile-shaped subkeys with garbage interface names, not real nested network
    interfaces -- confirmed by inspecting the raw real output, not a documented regipy
    feature this module relies on.
    """
    hive = _load_hive(system_path, "system")
    plugin = NetworkDataPlugin(hive, as_json=True)
    if not plugin.can_run():
        raise ParsingError(
            f"NetworkData plugin cannot run against {system_path}: not a SYSTEM hive."
        )
    try:
        plugin.run()
    except Exception as exc:
        raise ParsingError(f"NetworkData extraction failed for {system_path}: {exc}") from exc

    flattened: list[dict] = []
    for control_set_path, data in plugin.entries.items():
        for interface in data.get("interfaces", []):
            entry = {k: v for k, v in interface.items() if k != "sub_interface"}
            entry["key_path"] = f"{control_set_path}\\{interface.get('interface_name')}"
            flattened.append(entry)
    return flattened
