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
wrappers instead. This file is renamed and now holds genuinely plugin-less Phase 1 parsers.
"""

from __future__ import annotations

import struct
from pathlib import Path

from regipy.exceptions import RegistryKeyNotFoundException
from regipy.registry import RegistryHive
from regipy.utils import convert_wintime

from core.exceptions import ParsingError

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
    comparable records."""
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
    return flattened


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
