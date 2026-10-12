"""Custom, read-only parsers for registry artifacts that have no regipy plugin at all
(not even one that's wrong for the specific sub-case, as with extractors.py's
LastVisitedPidlMRU) -- confirmed by enumerating every module under regipy's own
`regipy.plugins` package before writing any of these, per this project's "use existing
regipy plugins where they exist; write custom parsers only where none exists" rule.

Hand-written against regipy's own public RegistryHive/NKRecord API
(RegistryHive.get_key(), NKRecord.get_value()/iter_values(), NKRecord.header.last_modified)
-- same "thin, read-only wrapper" shape extractors.py uses for regipy's own plugins, raising
ParsingError only if the hive itself can't be opened; a genuinely missing key/value is NOT
an error and degrades to an empty `list[dict]` result silently, same contract as every
extractor in extractors.py.

Formerly `system_context.py` (Phase 0: computer name/time zone/Windows version) -- those
three turned out to duplicate real regipy plugins (ComputerNamePlugin/TimezoneDataPlugin2/
WinVersionPlugin, missed in the first pass) and moved to extractors.py as thin plugin
wrappers instead. This file is renamed and now holds genuinely plugin-less parsers added
across Phase 1 (execution evidence) and Phase 2 (device evidence) of the roadmap.
"""

from __future__ import annotations

import struct
from pathlib import Path

from regipy.exceptions import RegistryKeyNotFoundException
from regipy.registry import RegistryHive
from regipy.utils import convert_wintime

from core.exceptions import ParsingError

from ._muicache_grouping import group_muicache_values
from .constants import extract_command_executable, is_tor_related, is_tor_service_name

# MUICache's Vista+ location is `\Software\Classes\Local Settings\Software\Microsoft\
# Windows\Shell\MuiCache` when read through the LIVE registry's HKCU view -- but that
# `\Software\Classes\` prefix is exactly the live virtual merge of UsrClass.dat *into*
# HKCU; it isn't a real subkey inside either hive's own file. UsrClass.dat's own root
# already corresponds to what HKCU\Software\Classes resolves to when mounted, so the
# real on-disk path, read directly from UsrClass.dat, drops that prefix entirely. This is
# exactly why regipy's own MUICachePlugin (COMPATIBLE_HIVE=ntuser, and its own Vista+
# path lookup still carries the dead `\Software\Classes\` prefix) can never actually find
# this data against either hive -- confirmed by reading that plugin's source, not guessed.
_MUICACHE_USRCLASS_PATH = r"\Local Settings\Software\Microsoft\Windows\Shell\MuiCache"

_COMPAT_ASSISTANT_STORE_PATH = r"\Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Store"
_FIREFOX_LAUNCHER_PATH = r"\Software\Mozilla\Firefox\Launcher"
_APP_SWITCHED_PATH = r"\Software\Microsoft\Windows\CurrentVersion\Explorer\FeatureUsage\AppSwitched"

# Phase 2 (device evidence) paths.
_MOUNTPOINTS2_PATH = r"\Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2"
_EMDMGMT_PATH = r"\Microsoft\Windows NT\CurrentVersion\EMDMgmt"
# Relative (no leading hive root) -- resolved per-ControlSet via RegistryHive.
# get_control_sets(), the same "every existing ControlSet, not just the active one"
# approach Phase 0's ComputerNamePlugin/TimezoneDataPlugin2 already use (extractors.py).
_WPD_RELATIVE_PATH = r"Enum\SWD\WPDBUSENUM"

# Phase 4 (persistence/configuration) paths. NTUSER's two Run paths are HKCU-only;
# SOFTWARE's four cover HKLM's native and WOW6432Node (32-bit-on-64-bit) views -- a 32-bit
# Tor Expert Bundle installer registers under WOW6432Node on a 64-bit Windows, same as any
# other 32-bit installer.
_NTUSER_RUN_PATHS = (
    r"\Software\Microsoft\Windows\CurrentVersion\Run",
    r"\Software\Microsoft\Windows\CurrentVersion\RunOnce",
)
_SOFTWARE_RUN_PATHS = (
    r"\Microsoft\Windows\CurrentVersion\Run",
    r"\Microsoft\Windows\CurrentVersion\RunOnce",
    r"\WOW6432Node\Microsoft\Windows\CurrentVersion\Run",
    r"\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce",
)
_SERVICES_PATH = "Services"
_INTERNET_SETTINGS_PATH = r"\Software\Microsoft\Windows\CurrentVersion\Internet Settings"


def _load_hive(hive_path: Path, hive_type: str) -> RegistryHive:
    """Deliberately duplicated from extractors.py's own _load_hive() rather than
    imported -- same reasoning acquire.py already gives for not importing pipeline.py:
    keeps this file's only dependency on the rest of the package at the public
    core.exceptions/regipy level, not on another module's private helper. See
    extractors.py's own _load_hive() docstring for why hive_type is always explicit
    rather than left to regipy's own (unreliable for a renamed/copied hive file)
    auto-detection."""
    try:
        return RegistryHive(str(hive_path), hive_type=hive_type)
    except Exception as exc:  # regipy raises its own exception hierarchy
        raise ParsingError(f"Could not open registry hive at {hive_path}: {exc}") from exc


def extract_muicache_usrclass(usrclass_path: Path) -> list[dict]:
    """MUICache (display names of apps invoked via the shell) from UsrClass.dat -- the
    actively-populated location on Windows Vista+; see the module-level note on
    _MUICACHE_USRCLASS_PATH for why regipy's own MUICachePlugin can't reach this data
    despite a same-named plugin existing. Mirrors that plugin's own value-filtering
    (skip "@..." indirect-string-table references and the "LangID" value) so the two
    sources (this one, and extract_muicache() from NTUSER.DAT) produce directly
    comparable records -- both also go through group_muicache_values() to merge Vista+'s
    FriendlyAppName/ApplicationCompany value pair for the same program into one finding
    (see that module's docstring)."""
    hive = _load_hive(usrclass_path, "usrclass")
    try:
        key = hive.get_key(_MUICACHE_USRCLASS_PATH)
    except RegistryKeyNotFoundException:
        return []
    except Exception as exc:
        raise ParsingError(f"MUICache (UsrClass.dat) extraction failed: {exc}") from exc

    last_write = convert_wintime(key.header.last_modified, as_json=True)
    flattened: list[dict] = []
    for value in key.iter_values():
        if value.name.startswith("@") or value.name == "LangID":
            continue
        display_name = value.value if isinstance(value.value, str) else None
        flattened.append(
            {
                "key_path": _MUICACHE_USRCLASS_PATH,
                "last_write": last_write,
                "path": value.name,
                "display_name": display_name,
                "filename": value.name.rsplit("\\", 1)[-1],
            }
        )
    return group_muicache_values(flattened)


def _best_effort_trailing_filetime(data: bytes) -> str | None:
    """AppCompatFlags\\Store's binary layout isn't documented here with certainty --
    best-effort only: the commonly-cited shape is a variable number of flag strings
    followed by an 8-byte FILETIME at the end of the blob. Returns None (not a guess)
    whenever the trailing 8 bytes don't decode to a plausible date, rather than ever
    presenting an implausible value as if it were reliable."""
    if len(data) < 8:
        return None
    try:
        raw = struct.unpack("<Q", data[-8:])[0]
        if raw == 0:
            return None
        decoded = convert_wintime(raw, as_json=False)
    except (struct.error, OverflowError, ValueError, OSError):
        return None
    if not (1990 <= decoded.year <= 2100):
        return None
    return decoded.isoformat()


def extract_compat_assistant_store(ntuser_path: Path) -> list[dict]:
    """Program Compatibility Assistant Store from NTUSER.DAT -- Windows' own record of
    executables it evaluated for compatibility problems (distinct from SOFTWARE's
    AppCompatFlags\\Layers/Custom, a different, machine-wide key about compatibility-mode
    *settings*, already covered by regipy's own AppCompatFlagsPlugin if that's ever
    wired in separately). The value NAME -- the full executable path -- is the actual
    evidence and is NOT best-effort; the value DATA's trailing-FILETIME decode is (see
    _best_effort_trailing_filetime), and is kept as supplementary detail, not promoted
    into Artifact.timestamp, so a wrong best-effort guess can never look authoritative."""
    hive = _load_hive(ntuser_path, "ntuser")
    try:
        key = hive.get_key(_COMPAT_ASSISTANT_STORE_PATH)
    except RegistryKeyNotFoundException:
        return []
    except Exception as exc:
        raise ParsingError(f"CompatAssistantStore extraction failed: {exc}") from exc

    last_write = convert_wintime(key.header.last_modified, as_json=True)
    flattened: list[dict] = []
    for value in key.iter_values(trim_values=False):
        data = value.value if isinstance(value.value, bytes) else b""
        flattened.append(
            {
                "key_path": _COMPAT_ASSISTANT_STORE_PATH,
                "last_write": last_write,
                "path": value.name,
                "flagged_timestamp": _best_effort_trailing_filetime(data),
                "data_size": len(data),
            }
        )
    return flattened


def extract_firefox_launcher(ntuser_path: Path) -> list[dict]:
    """Software\\Mozilla\\Firefox\\Launcher from NTUSER.DAT -- Firefox-family browsers
    (Tor Browser included) record their own full executable path here as a value NAME
    each time they launch; that path is the evidence, and is already a full path, so the
    existing is_tor_related() substring markers apply unchanged. The value DATA's exact
    meaning isn't documented here with confidence -- kept only as a raw supplementary
    field, never interpreted as a timestamp or otherwise promoted."""
    hive = _load_hive(ntuser_path, "ntuser")
    try:
        key = hive.get_key(_FIREFOX_LAUNCHER_PATH)
    except RegistryKeyNotFoundException:
        return []
    except Exception as exc:
        raise ParsingError(f"FirefoxLauncher extraction failed: {exc}") from exc

    last_write = convert_wintime(key.header.last_modified, as_json=True)
    flattened: list[dict] = []
    for value in key.iter_values(trim_values=False):
        flattened.append(
            {
                "key_path": _FIREFOX_LAUNCHER_PATH,
                "last_write": last_write,
                "path": value.name,
                "raw_value": repr(value.value),
            }
        )
    return flattened


def extract_app_switched(ntuser_path: Path) -> list[dict]:
    """FeatureUsage\\AppSwitched from NTUSER.DAT -- a DWORD count, per app identifier, of
    how many times that app was switched to via Alt+Tab/the taskbar. Sibling of
    UserAssist, but corroborating only: shows the window was switched TO, not that it was
    launched by this mechanism."""
    hive = _load_hive(ntuser_path, "ntuser")
    try:
        key = hive.get_key(_APP_SWITCHED_PATH)
    except RegistryKeyNotFoundException:
        return []
    except Exception as exc:
        raise ParsingError(f"AppSwitched extraction failed: {exc}") from exc

    last_write = convert_wintime(key.header.last_modified, as_json=True)
    flattened: list[dict] = []
    for value in key.iter_values():
        count = value.value if isinstance(value.value, int) else None
        flattened.append(
            {
                "key_path": _APP_SWITCHED_PATH,
                "last_write": last_write,
                "path": value.name,
                "switch_count": count,
            }
        )
    return flattened


def extract_mountpoints2(ntuser_path: Path) -> list[dict]:
    """Per-user record (one entry per mounted volume this user's session has seen) from
    NTUSER.DAT's MountPoints2 -- subkey names are typically a volume GUID or, for a USB
    drive, the same _??_USBSTOR#...#<serial>#{GUID} identifier MountedDevices/USBSTOR
    also use (report.py's device correlation can match on this)."""
    hive = _load_hive(ntuser_path, "ntuser")
    try:
        key = hive.get_key(_MOUNTPOINTS2_PATH)
    except RegistryKeyNotFoundException:
        return []
    except Exception as exc:
        raise ParsingError(f"MountPoints2 extraction failed: {exc}") from exc

    flattened: list[dict] = []
    for subkey in key.iter_subkeys():
        flattened.append(
            {
                "key_path": f"{_MOUNTPOINTS2_PATH}\\{subkey.name}",
                "path": subkey.name,
                "last_write": convert_wintime(subkey.header.last_modified, as_json=True),
            }
        )
    return flattened


def extract_emdmgmt(software_path: Path) -> list[dict]:
    """External Mass Device Management (ReadyBoost-eligibility testing) records from
    SOFTWARE's EMDMgmt -- an independent OS subsystem corroborating removable-device
    presence. Best-effort on exact value layout (no regipy plugin or sample to verify
    against, same honesty standard as Phase 1's AppCompatFlags\\Store/Firefox Launcher):
    the subkey name (device identity, embedding the same vendor/product/serial shape) is
    reliable; incidental value fields are supplementary."""
    hive = _load_hive(software_path, "software")
    try:
        key = hive.get_key(_EMDMGMT_PATH)
    except RegistryKeyNotFoundException:
        return []
    except Exception as exc:
        raise ParsingError(f"EMDMgmt extraction failed: {exc}") from exc

    flattened: list[dict] = []
    for subkey in key.iter_subkeys():
        flattened.append(
            {
                "key_path": f"{_EMDMGMT_PATH}\\{subkey.name}",
                "path": subkey.name,
                "device_capacity": subkey.get_value("DeviceCapacity"),
                "last_write": convert_wintime(subkey.header.last_modified, as_json=True),
            }
        )
    return flattened


def extract_portable_devices(system_path: Path) -> list[dict]:
    """Windows Portable Devices (MTP device history, e.g. phones/cameras) from SYSTEM's
    Enum\\SWD\\WPDBUSENUM -- tangential to a mass-storage Tor install but still
    device-connection context. Resolved per existing ControlSet via
    RegistryHive.get_control_sets(), same approach extractors.py's ComputerNamePlugin/
    TimezoneDataPlugin2 wrappers already rely on."""
    hive = _load_hive(system_path, "system")
    flattened: list[dict] = []
    for control_set_path in hive.get_control_sets(_WPD_RELATIVE_PATH):
        try:
            key = hive.get_key(control_set_path)
        except RegistryKeyNotFoundException:
            continue
        except Exception as exc:
            raise ParsingError(f"PortableDevices extraction failed: {exc}") from exc
        for device_key in key.iter_subkeys():
            flattened.append(
                {
                    "key_path": f"{control_set_path}\\{device_key.name}",
                    "path": device_key.name,
                    "friendly_name": device_key.get_value("FriendlyName"),
                    "last_write": convert_wintime(device_key.header.last_modified, as_json=True),
                }
            )
    return flattened


# ---------------------------------------------------------------------------
# Phase 4 of the Module A roadmap -- persistence and configuration.
# ---------------------------------------------------------------------------


def _extract_run_keys(hive: RegistryHive, paths: tuple[str, ...]) -> list[dict]:
    """Shared body for the NTUSER/SOFTWARE Run-key extractors below -- each Run/RunOnce
    key is a flat list of value_name -> command_line pairs with no subkeys. `executable`
    is the command line with any quoting/arguments stripped (see
    constants.extract_command_executable()'s docstring for why this step is required --
    is_tor_related()'s basename check cannot match a raw command line like
    '"C:\\Tor\\tor.exe" --service' on its own)."""
    flattened: list[dict] = []
    for path in paths:
        try:
            key = hive.get_key(path)
        except RegistryKeyNotFoundException:
            continue
        except Exception as exc:
            raise ParsingError(f"RunKey extraction failed at {path}: {exc}") from exc
        last_write = convert_wintime(key.header.last_modified, as_json=True)
        for value in key.iter_values():
            command = value.value if isinstance(value.value, str) else None
            flattened.append(
                {
                    "key_path": path,
                    "name": value.name,
                    "command": command,
                    "executable": extract_command_executable(command),
                    "last_write": last_write,
                }
            )
    return flattened


def extract_run_keys_ntuser(ntuser_path: Path) -> list[dict]:
    """Run/RunOnce (HKCU, via NTUSER.DAT) -- the per-user autostart locations."""
    hive = _load_hive(ntuser_path, "ntuser")
    return _extract_run_keys(hive, _NTUSER_RUN_PATHS)


def extract_run_keys_software(software_path: Path) -> list[dict]:
    """Run/RunOnce (HKLM, via SOFTWARE, native + WOW6432Node) -- the machine-wide autostart
    locations. Shares ARTIFACT_TYPE_RUNKEY with extract_run_keys_ntuser() above -- same
    kind of evidence (an autostart entry), just two possible source hives depending on
    whether the entry is per-user or machine-wide; Artifact.source differentiates."""
    hive = _load_hive(software_path, "software")
    return _extract_run_keys(hive, _SOFTWARE_RUN_PATHS)


def extract_services(system_path: Path) -> list[dict]:
    """Tor-related Windows services from SYSTEM's Services key.

    Deliberately NOT regipy's own ServicesPlugin, and deliberately NOT a plain
    "read every service's full value set" loop either -- both were measured against a
    real SYSTEM hive (858 services) and are far too slow for what is, in the overwhelming
    majority of cases, a search that finds nothing: ServicesPlugin's own recursive
    per-service parameter walk took ~76 seconds; even a single unconditional
    iter_values() per service (no recursion at all) took ~30 seconds -- regipy parses
    every value's data unconditionally with no cheaper per-name fast path, confirmed by
    timing a bare iter_subkeys() pass (instant) against one that also touches values.

    Instead, a cheap first pass reads only each service's own name and ImagePath (a single
    get_value() call -- confirmed ~7.5s for 858 real services, acceptable for a one-time
    forensic step) to decide relevance via the exact same predicates
    is_tor_related_entry() applies afterward (constants.is_tor_service_name() on the name,
    is_tor_related() on the stripped executable) -- duplicated here deliberately so the
    expensive full iter_values() read below is skipped for every service that will be
    filtered out anyway; only a match gets the fuller read (DisplayName/Start/ObjectName/
    Description). This is a real, measured performance requirement, not a hypothetical
    one: a naive "tor" substring search was also tried during development and rejected --
    on a real machine, "DriverStore" alone (present in most driver ImagePaths) contains
    "tor" as a substring of "Store", producing hundreds of false positives.

    A service that doesn't reference Tor at all is never returned, same "Module A doesn't
    report every autostart entry" principle as RunKey -- this extractor does its own
    relevance pre-filtering for performance, but every returned entry would also pass the
    normal is_tor_related_entry() gate pipeline.py applies afterward (redundant, but
    harmless given how few entries make it this far).
    """
    hive = _load_hive(system_path, "system")
    flattened: list[dict] = []
    for control_set_path in hive.get_control_sets(_SERVICES_PATH):
        try:
            services_key = hive.get_key(control_set_path)
        except RegistryKeyNotFoundException:
            continue
        except Exception as exc:
            raise ParsingError(f"Services extraction failed at {control_set_path}: {exc}") from exc

        for service_key in services_key.iter_subkeys():
            name = service_key.name
            image_path = service_key.get_value("ImagePath")
            image_path = image_path if isinstance(image_path, str) else None
            executable = extract_command_executable(image_path)
            if not (is_tor_service_name(name) or is_tor_related(executable)):
                continue

            flattened.append(
                {
                    "key_path": f"{control_set_path}\\{name}",
                    "name": name,
                    "image_path": image_path,
                    "executable": executable,
                    "display_name": service_key.get_value("DisplayName"),
                    "start": service_key.get_value("Start"),
                    "object_name": service_key.get_value("ObjectName"),
                    "last_write": convert_wintime(service_key.header.last_modified, as_json=True),
                }
            )
    return flattened


def extract_proxy_settings(ntuser_path: Path) -> list[dict]:
    """Internet Settings proxy configuration (HKCU, via NTUSER.DAT) -- ProxyEnable/
    ProxyServer/AutoConfigURL. A single record (at most one per hive, since there's only
    one Internet Settings key), returned as a one-item list for a uniform shape with every
    other extractor here. Relevance (is this Tor-related at all) is decided entirely by
    constants.is_tor_proxy_config() downstream, not here -- see that function's docstring
    for why "enabled AND pointing at a Tor SOCKS port" isn't a path-substring question."""
    hive = _load_hive(ntuser_path, "ntuser")
    try:
        key = hive.get_key(_INTERNET_SETTINGS_PATH)
    except RegistryKeyNotFoundException:
        return []
    except Exception as exc:
        raise ParsingError(f"ProxySettings extraction failed: {exc}") from exc

    return [
        {
            "key_path": _INTERNET_SETTINGS_PATH,
            "proxy_enable": key.get_value("ProxyEnable"),
            "proxy_server": key.get_value("ProxyServer"),
            "auto_config_url": key.get_value("AutoConfigURL"),
            "last_write": convert_wintime(key.header.last_modified, as_json=True),
        }
    ]
