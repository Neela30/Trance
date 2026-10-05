"""Converts each artifact type's raw regipy dict into the shared Artifact schema.

Per Module A Description 2.4 ("Confidence annotation"): ShimCache reflects
insertion order, not confirmed execution, and that caveat must be encoded
directly in the output schema, not left to report prose alone.

As of Phase 0 of the Module A roadmap, confidence/category are structured
`core.schema.Artifact` fields (`confidence`, `confidence_reason`, `category`),
assigned uniformly for every artifact_type by `normalize_entry()` itself from
`constants.ARTIFACT_CONFIDENCE` / `ARTIFACT_CONFIDENCE_REASON` / `ARTIFACT_CATEGORY`
— a single source of truth, no longer duplicated between this file's prose and
report.py's own map. Each `_normalize_*` function below is now only responsible
for the plain factual `description` (what the entry says), not confidence.

Confidence levels assigned (per 2.2 / 2.4 of the project brief; see
constants.py for the full per-type table):
  - UserAssist : HIGH  — GUI-launched execution evidence.
  - Amcache    : HIGH  — persists largely independent of execution/shutdown.
  - ShimCache  : MEDIUM — insertion-order evidence only, not confirmed execution.
  - RecentDocs : LOW   — contextual/corroborating evidence only.
"""

from __future__ import annotations

from core.schema import Artifact

from .constants import (
    ARTIFACT_CATEGORY,
    ARTIFACT_CONFIDENCE,
    ARTIFACT_CONFIDENCE_REASON,
    ARTIFACT_TYPE_AMCACHE,
    ARTIFACT_TYPE_APP_SWITCHED,
    ARTIFACT_TYPE_BAM,
    ARTIFACT_TYPE_COMDLG32,
    ARTIFACT_TYPE_COMPAT_ASSISTANT_STORE,
    ARTIFACT_TYPE_COMPUTERNAME,
    ARTIFACT_TYPE_EMDMGMT,
    ARTIFACT_TYPE_FIREFOX_LAUNCHER,
    ARTIFACT_TYPE_INSTALLEDPROGRAMS,
    ARTIFACT_TYPE_LASTVISITEDPIDLMRU,
    ARTIFACT_TYPE_MOUNTEDDEVICES,
    ARTIFACT_TYPE_MOUNTPOINTS2,
    ARTIFACT_TYPE_MUICACHE,
    ARTIFACT_TYPE_NETWORK_INTERFACE,
    ARTIFACT_TYPE_NETWORK_PROFILE,
    ARTIFACT_TYPE_PORTABLEDEVICES,
    ARTIFACT_TYPE_PROXY_SETTINGS,
    ARTIFACT_TYPE_RECENTDOCS,
    ARTIFACT_TYPE_RUNKEY,
    ARTIFACT_TYPE_RUNMRU,
    ARTIFACT_TYPE_SERVICE,
    ARTIFACT_TYPE_SHELLBAGS,
    ARTIFACT_TYPE_SHIMCACHE,
    ARTIFACT_TYPE_TIMEZONE,
    ARTIFACT_TYPE_TYPEDPATHS,
    ARTIFACT_TYPE_USBDEVICES,
    ARTIFACT_TYPE_USBSTOR,
    ARTIFACT_TYPE_USER_ASSIST,
    ARTIFACT_TYPE_WINDOWSVERSION,
    ARTIFACT_TYPE_WORDWHEELQUERY,
    CATEGORY_TOR_DIRECT,
    candidate_path,
)

MODULE_NAME = "module_a_registry"

# Windows FILETIME's epoch is 1601-01-01 -- a raw FILETIME value of 0 (field never set)
# converts to exactly that date, which regipy hands back as an ordinary-looking
# timestamp. Left alone, "no timestamp recorded" displays as a real-looking date 425
# years in the past; this catches that sentinel and turns it back into None, regardless
# of which artifact type or sub-second precision produced it.
_NULL_FILETIME_DATE = "1601-01-01"


def _clean_timestamp(timestamp: str | None) -> str | None:
    if timestamp and timestamp.startswith(_NULL_FILETIME_DATE):
        return None
    return timestamp


def _first(entry: dict, keys: tuple[str, ...]) -> object | None:
    for key in keys:
        value = entry.get(key)
        if value:
            return value
    return None


def _normalize_user_assist(entry: dict) -> tuple[str, str | None]:
    path = candidate_path(ARTIFACT_TYPE_USER_ASSIST, entry) or "<unknown>"
    details = [f"run_count={entry.get('run_counter')}"]
    if entry.get("focus_count") is not None:
        details.append(f"focus_count={entry.get('focus_count')}")
    if entry.get("total_focus_time_ms") is not None:
        details.append(f"total_focus_time_ms={entry.get('total_focus_time_ms')}")
    description = f"UserAssist evidence for '{path}' ({', '.join(details)})."
    return description, entry.get("timestamp")


def _normalize_shimcache(entry: dict) -> tuple[str, str | None]:
    path = candidate_path(ARTIFACT_TYPE_SHIMCACHE, entry) or "<unknown>"
    timestamp = _first(entry, ("last_mod_date", "last_mod_time", "exec_time", "last_update"))
    description = f"ShimCache/AppCompatCache entry for '{path}'."
    return description, timestamp


def _normalize_amcache(entry: dict) -> tuple[str, str | None]:
    path = candidate_path(ARTIFACT_TYPE_AMCACHE, entry) or "<unknown>"
    details = []
    sha1 = entry.get("sha1")
    if sha1:
        details.append(f"sha1={sha1}")
    size = entry.get("size", entry.get("file_size"))
    if size is not None:
        details.append(f"size={size}")
    detail_suffix = f" ({', '.join(details)})" if details else ""
    description = f"Amcache install/first-seen evidence for '{path}'{detail_suffix}."
    timestamp = entry.get("timestamp") or entry.get("created_timestamp")
    return description, timestamp


def _normalize_recentdocs(entry: dict) -> tuple[str, str | None]:
    name = candidate_path(ARTIFACT_TYPE_RECENTDOCS, entry) or "<unknown>"
    extension = entry.get("extension")
    ext_suffix = f", extension={extension}" if extension else ""
    description = f"RecentDocs entry '{name}'{ext_suffix} — recently accessed file."
    return description, entry.get("last_write")


def _normalize_bam(entry: dict) -> tuple[str, str | None]:
    path = candidate_path(ARTIFACT_TYPE_BAM, entry) or "<unknown>"
    sid = entry.get("sid")
    sid_suffix = f", sid={sid}" if sid else ""
    description = (
        f"BAM (Background Activity Moderator) last-execution evidence for '{path}'{sid_suffix}."
    )
    return description, entry.get("timestamp")


def _normalize_muicache(entry: dict) -> tuple[str, str | None]:
    # entry has already been through _muicache_grouping.group_muicache_values() (called
    # from the extractor itself) -- "display_name"/"application_company" here are the
    # Vista+ FriendlyAppName/ApplicationCompany value pair for the SAME program merged
    # into one record, not two separate findings. "path" is the base executable path with
    # the ".FriendlyAppName"/".ApplicationCompany" suffix already stripped.
    path = candidate_path(ARTIFACT_TYPE_MUICACHE, entry) or "<unknown>"
    display_name = entry.get("display_name")
    company = entry.get("application_company")
    details = []
    if display_name:
        details.append(repr(display_name))
    if company:
        details.append(company)
    detail_suffix = f" — {', '.join(details)}" if details else ""
    description = f"MUICache entry for '{path}'{detail_suffix}."
    return description, entry.get("last_write")


def _normalize_runmru(entry: dict) -> tuple[str, str | None]:
    # "for '...'" wording is required here, not just stylistic -- report.py's
    # _PATH_RE (shared by every artifact type) only matches "for '...'"/"entry '...'",
    # and without a match this entry would silently drop out of the cross-hive
    # component correlation table entirely.
    command = candidate_path(ARTIFACT_TYPE_RUNMRU, entry) or "<unknown>"
    description = f"RunMRU evidence for '{command}' (command typed into the Run dialog)."
    return description, entry.get("last_write")


def _normalize_word_wheel_query(entry: dict) -> tuple[str, str | None]:
    # See _normalize_runmru's comment -- "for '...'" wording is load-bearing for
    # report.py's _PATH_RE, not just stylistic.
    query = candidate_path(ARTIFACT_TYPE_WORDWHEELQUERY, entry) or "<unknown>"
    description = (
        f"WordWheelQuery evidence for '{query}' (search typed into Explorer/Start search)."
    )
    return description, entry.get("last_write")


def _normalize_comdlg32(entry: dict) -> tuple[str, str | None]:
    path = candidate_path(ARTIFACT_TYPE_COMDLG32, entry) or "<unknown>"
    mru_type = entry.get("mru_type")
    type_suffix = f" ({mru_type})" if mru_type else ""
    description = f"ComDlg32 entry for '{path}'{type_suffix} — used in a file Open/Save dialog."
    return description, entry.get("last_write")


def _normalize_installed_programs(entry: dict) -> tuple[str, str | None]:
    path = candidate_path(ARTIFACT_TYPE_INSTALLEDPROGRAMS, entry) or "<unknown>"
    publisher = entry.get("Publisher")
    publisher_suffix = f", publisher={publisher!r}" if publisher else ""
    # InstallDate (when present) is the Uninstall key's own raw "YYYYMMDD" string, not
    # ISO-8601 -- kept in the description as context rather than as Artifact.timestamp
    # (which every other type here treats as a parseable ISO timestamp). The key's own
    # last-write time (already ISO, via regipy's convert_wintime) is the real timestamp.
    install_date = entry.get("InstallDate")
    date_suffix = f", InstallDate={install_date}" if install_date else ""
    description = (
        f"Installed-programs (Uninstall key) entry for '{path}'{publisher_suffix}{date_suffix}."
    )
    return description, entry.get("timestamp")


def _normalize_computer_name(entry: dict) -> tuple[str, str | None]:
    # ComputerNamePlugin's own entry key is "name", not "computer_name" -- matched here
    # exactly as the plugin returns it (see extractors.extract_computer_name()).
    name = entry.get("name") or "<unknown>"
    description = f"Computer name recorded as '{name}'."
    return description, entry.get("timestamp")


def _normalize_time_zone(entry: dict) -> tuple[str, str | None]:
    # TimezoneDataPlugin2's own entry keys are "TimeZoneKeyName"/"Bias" (PascalCase, as
    # regipy emits them) -- NOT "time_zone_key_name"/"bias". A real-hive check (Phase 3
    # of the Module A roadmap) found this function had always read the wrong-cased keys
    # since Phase 0, so it silently fell back to "<unknown>" with no bias on every real
    # acquisition; the hand-built test fixtures used the same wrong casing, which is why
    # ~210 passing tests never caught it. Fixed here to match extract_time_zone()'s real
    # output (see extractors.py) -- Phase 3's local-time-to-UTC conversion for NetworkList
    # timestamps depends on a working Bias value, which is what surfaced this.
    tz_name = entry.get("TimeZoneKeyName") or "<unknown>"
    bias = entry.get("Bias")
    bias_suffix = f", bias={bias} minutes from UTC" if bias is not None else ""
    description = f"Windows time zone configured as '{tz_name}'{bias_suffix}."
    return description, entry.get("last_write")


def _normalize_windows_version(entry: dict) -> tuple[str, str | None]:
    # Same real-hive-confirmed bug as _normalize_time_zone() above: WinVersionPlugin's own
    # entry keys are "ProductName"/"CurrentVersion"/"CurrentBuildNumber" (PascalCase), not
    # the snake_case names this function read since Phase 0 -- always fell back to
    # "<unknown>" against real evidence. Fixed to match extract_windows_version()'s real
    # output.
    product = entry.get("ProductName") or "<unknown>"
    details = []
    if entry.get("CurrentVersion"):
        details.append(f"version={entry['CurrentVersion']}")
    if entry.get("CurrentBuildNumber"):
        details.append(f"build={entry['CurrentBuildNumber']}")
    detail_suffix = f" ({', '.join(details)})" if details else ""
    description = f"Windows version recorded as '{product}'{detail_suffix}."
    return description, entry.get("last_write")


def _normalize_shellbags(entry: dict) -> tuple[str, str | None]:
    path = candidate_path(ARTIFACT_TYPE_SHELLBAGS, entry) or "<unknown>"
    description = f"ShellBags entry for '{path}' — folder browsed in Explorer."
    return description, entry.get("last_write")


def _normalize_compat_assistant_store(entry: dict) -> tuple[str, str | None]:
    path = candidate_path(ARTIFACT_TYPE_COMPAT_ASSISTANT_STORE, entry) or "<unknown>"
    flagged = entry.get("flagged_timestamp")
    flagged_suffix = (
        f" (best-effort flagged time: {flagged})" if flagged else " (flagged time: not decoded)"
    )
    description = f"Program Compatibility Assistant Store entry for '{path}'{flagged_suffix}."
    return description, entry.get("last_write")


def _normalize_firefox_launcher(entry: dict) -> tuple[str, str | None]:
    path = candidate_path(ARTIFACT_TYPE_FIREFOX_LAUNCHER, entry) or "<unknown>"
    description = f"Firefox Launcher entry for '{path}'."
    return description, entry.get("last_write")


def _normalize_app_switched(entry: dict) -> tuple[str, str | None]:
    path = candidate_path(ARTIFACT_TYPE_APP_SWITCHED, entry) or "<unknown>"
    count = entry.get("switch_count")
    count_suffix = f" (switch_count={count})" if count is not None else ""
    description = f"AppSwitched entry for '{path}'{count_suffix} — switched to via Alt+Tab/taskbar."
    return description, entry.get("last_write")


def _normalize_typed_paths(entry: dict) -> tuple[str, str | None]:
    # "for '...'" wording is load-bearing for report.py's _PATH_RE, same as RunMRU/
    # WordWheelQuery above.
    path = candidate_path(ARTIFACT_TYPE_TYPEDPATHS, entry) or "<unknown>"
    description = f"TypedPaths evidence for '{path}' (path typed into Explorer's address bar)."
    return description, entry.get("last_write")


def _normalize_last_visited_pidl_mru(entry: dict) -> tuple[str, str | None]:
    # "entry for '...'" wording is load-bearing for report.py's _PATH_RE, same as
    # RunMRU/WordWheelQuery/TypedPaths above -- must come before the "program" mention so
    # _extract_path()'s first regex match is the folder, not the program.
    path = candidate_path(ARTIFACT_TYPE_LASTVISITEDPIDLMRU, entry) or "<unknown>"
    program = entry.get("program")
    program_suffix = f", last visited by '{program}'" if program else ""
    description = f"LastVisitedPidlMRU entry for '{path}'{program_suffix}."
    return description, entry.get("last_write")


def _normalize_usbstor(entry: dict) -> tuple[str, str | None]:
    # No candidate_path() entry (deliberate -- context-category types read their own
    # named fields directly, same precedent as Phase 0/1's context facts). device_name
    # is the Properties subkey's friendly name when present; title is USBSTOR's own
    # parsed-from-subkey-name fallback (e.g. "Cruzer_Blade"). manufacturer=/serial=/
    # first_connected=/last_connected= are ALWAYS present in the description (never
    # dropped as an optional suffix) so report.py's device correlation
    # (_build_device_correlation()) can parse them with a single unconditional regex
    # rather than guessing which optional clauses are there. first_connected is the raw
    # entry's own "first_installed" field (USBSTOR's closest equivalent to "first seen" --
    # when Windows first set up a driver for this device), named "first_connected" here to
    # match the plain-English vocabulary the device-correlation narrative uses.
    name = entry.get("device_name") or entry.get("title") or "<unknown>"
    serial = entry.get("serial_number") or "unknown"
    manufacturer = entry.get("manufacturer") or "unknown"
    first_connected = entry.get("first_installed") or "unknown"
    last_connected = entry.get("last_connected") or "unknown"
    description = (
        f"USBSTOR device '{name}' (manufacturer={manufacturer}, serial={serial}, "
        f"first_connected={first_connected}, last_connected={last_connected}) "
        "— USB mass-storage connection history."
    )
    timestamp = _first(entry, ("last_connected", "last_installed", "first_installed", "last_write"))
    return description, timestamp


def _normalize_usb_devices(entry: dict) -> tuple[str, str | None]:
    name = (
        entry.get("friendly_name")
        or entry.get("device_desc")
        or entry.get("vid_pid")
        or "<unknown>"
    )
    vid = entry.get("vid") or "unknown"
    pid = entry.get("pid") or "unknown"
    description = f"USB device '{name}' (vid={vid}, pid={pid}) enumerated by Windows."
    return description, entry.get("last_write")


def _normalize_mounted_devices(entry: dict) -> tuple[str, str | None]:
    mount_point = entry.get("mount_point") or entry.get("value_name") or "<unknown>"
    mount_type = entry.get("mount_type") or "other"
    # "dynamic_disk_identifier" is a literal sentinel report.py's device correlation
    # checks for by exact string match (_build_device_correlation()) -- set by
    # extractors.extract_mounted_devices() when a value's raw bytes start with the
    # Windows Dynamic Disk ("DMIO:ID:") prefix, a format regipy's own parse_device_data()
    # doesn't recognize (nor should it -- it's an undocumented LDM object id, not a path/
    # signature/GUID). Distinguished from the honest "not decoded" case (bytes present but
    # genuinely unrecognized) so the correlation logic can tell "this drive is structurally
    # not a USB stick" (Windows disallows dynamic disks on removable media) apart from
    # "we simply don't know".
    if entry.get("dynamic_disk"):
        decoded = "dynamic_disk_identifier"
    else:
        decoded = (
            entry.get("path")
            or entry.get("disk_signature")
            or entry.get("disk_guid")
            or "not decoded"
        )
    volume_guid = entry.get("volume_guid") or "none"
    description = (
        f"MountedDevices entry '{mount_point}' (mount_type={mount_type}, decoded={decoded}, "
        f"volume_guid={volume_guid})."
    )
    return description, entry.get("last_write")


def _normalize_mountpoints2(entry: dict) -> tuple[str, str | None]:
    path = entry.get("path") or "<unknown>"
    description = f"MountPoints2 entry '{path}' — volume mounted by this user's session."
    return description, entry.get("last_write")


def _normalize_emdmgmt(entry: dict) -> tuple[str, str | None]:
    path = entry.get("path") or "<unknown>"
    capacity = entry.get("device_capacity")
    capacity_str = capacity if capacity is not None else "unknown"
    description = (
        f"EMDMgmt entry '{path}' (device_capacity={capacity_str}) "
        "— ReadyBoost device-eligibility test record."
    )
    return description, entry.get("last_write")


def _normalize_portable_devices(entry: dict) -> tuple[str, str | None]:
    # `path` (the raw WPD subkey name) often embeds the same USBSTOR-shaped identifier
    # (including the serial number) MountedDevices/USBSTOR/MountPoints2 also use --
    # confirmed against real evidence for a USB mass-storage device also enumerated via
    # WPD. When a human-readable `friendly_name` is present it's shown as the quoted
    # name instead (more useful to a reader), which would otherwise hide that raw
    # identifier entirely -- so it's always rendered separately via device_id= (never
    # omitted) for report.py's device correlation to join on.
    raw_path = entry.get("path") or "<unknown>"
    name = entry.get("friendly_name") or raw_path
    description = (
        f"Windows Portable Devices entry '{name}' (device_id={raw_path}) "
        "— MTP/portable device history."
    )
    return description, entry.get("last_write")


def _stringify(value: object) -> str | None:
    """Several NetworkData/NetworkList fields come back as a list (e.g.
    dhcp_default_gateway=['192.168.1.1'], confirmed against a real SYSTEM hive -- Windows
    allows more than one gateway per interface even though only one is typically
    configured) -- joined here into a single comma-separated string so every description
    below can treat it as plain text."""
    if value is None:
        return None
    if isinstance(value, (list, tuple)):
        return ", ".join(str(v) for v in value) if value else None
    return str(value)


def _normalize_network_profile(entry: dict) -> tuple[str, str | None]:
    # Every field rendered unconditionally with an "unknown" sentinel (never an optional
    # suffix that may be absent) -- same convention Phase 2's USBStor/MountedDevices
    # normalizers use, so report.py's own regex-based parsing (the only way a `description`
    # string round-trips structured data back to the report layer) can assume a match
    # always exists. date_created_local/date_last_connected_local are deliberately NOT
    # promoted to Artifact.timestamp (which every other artifact type treats as UTC) --
    # these are SYSTEMTIME values in the machine's own LOCAL time (confirmed by decoding a
    # real value), and silently treating a local time as UTC elsewhere (sorting, "most
    # recent" comparisons) would misrepresent it by the system's own UTC offset. report.py/
    # narrative.py convert these explicitly using the system's recorded TimeZone bias
    # (Phase 0) wherever they're compared against a UTC timestamp.
    name = entry.get("profile_name") or entry.get("profile_guid") or "<unknown>"
    name_type = entry.get("name_type") or "unknown"
    category = entry.get("category") or "unknown"
    created = entry.get("date_created_local") or "unknown"
    last_connected = entry.get("date_last_connected_local") or "unknown"
    mac = entry.get("default_gateway_mac") or "unknown"
    dns_suffix = entry.get("dns_suffix") or "unknown"
    description = (
        f"Network profile '{name}' (type={name_type}, category={category}, "
        f"created_local={created}, last_connected_local={last_connected}, "
        f"gateway_mac={mac}, dns_suffix={dns_suffix})."
    )
    return description, None


def _normalize_network_interface(entry: dict) -> tuple[str, str | None]:
    # Unlike NetworkProfile's local-time fields above, dhcp_lease_obtained_time/
    # dhcp_lease_terminates_time genuinely ARE UTC already -- regipy's NetworkDataPlugin
    # converts the raw Unix-epoch DWORD via datetime.fromtimestamp(..., timezone.utc)
    # (confirmed by reading its source and cross-checking against a real lease on a real
    # hive) -- so, unlike NetworkProfile, Artifact.timestamp here (last_modified, the
    # interface key's own last-write time) is a normal UTC value like every other type.
    name = entry.get("interface_name") or "<unknown>"
    if entry.get("dhcp_enabled"):
        ip = _stringify(entry.get("dhcp_ip_address")) or "unknown"
        gateway = _stringify(entry.get("dhcp_default_gateway")) or "unknown"
        dhcp_server = _stringify(entry.get("dhcp_server")) or "unknown"
        lease_obtained = entry.get("dhcp_lease_obtained_time") or "unknown"
        lease_terminates = entry.get("dhcp_lease_terminates_time") or "unknown"
        domain = entry.get("dhcp_domain") or "unknown"
        description = (
            f"Network interface '{name}' (dhcp=yes, ip={ip}, gateway={gateway}, "
            f"dhcp_server={dhcp_server}, lease_obtained_utc={lease_obtained}, "
            f"lease_terminates_utc={lease_terminates}, domain={domain})."
        )
    else:
        ip = _stringify(entry.get("ip_address")) or "unknown"
        gateway = _stringify(entry.get("default_gateway")) or "unknown"
        domain = entry.get("domain") or "unknown"
        description = (
            f"Network interface '{name}' (dhcp=no, ip={ip}, gateway={gateway}, "
            f"domain={domain})."
        )
    return description, entry.get("last_modified")


def _normalize_run_key(entry: dict) -> tuple[str, str | None]:
    path = candidate_path(ARTIFACT_TYPE_RUNKEY, entry) or "<unknown>"
    name = entry.get("name") or "<unknown>"
    key_path = entry.get("key_path") or "unknown"
    description = (
        f"RunKey entry '{path}' (value name={name!r}, key={key_path}) "
        "— configured to start automatically."
    )
    return description, entry.get("last_write")


def _normalize_service(entry: dict) -> tuple[str, str | None]:
    path = candidate_path(ARTIFACT_TYPE_SERVICE, entry) or "<unknown>"
    name = entry.get("name") or "<unknown>"
    start = entry.get("start")
    start_suffix = f", start={start}" if start is not None else ""
    description = (
        f"Service entry for '{path}' (service name={name!r}{start_suffix}) "
        "— installed as a Windows service."
    )
    return description, entry.get("last_write")


def _normalize_proxy_settings(entry: dict) -> tuple[str, str | None]:
    proxy_server = entry.get("proxy_server") or "unknown"
    enabled = "yes" if entry.get("proxy_enable") == 1 else "no"
    auto_config = entry.get("auto_config_url") or "none"
    description = (
        f"Internet Settings proxy configuration (enabled={enabled}, server={proxy_server}, "
        f"auto_config_url={auto_config}) — other programs routed through this proxy."
    )
    return description, entry.get("last_write")


_NORMALIZERS = {
    ARTIFACT_TYPE_USER_ASSIST: _normalize_user_assist,
    ARTIFACT_TYPE_SHIMCACHE: _normalize_shimcache,
    ARTIFACT_TYPE_AMCACHE: _normalize_amcache,
    ARTIFACT_TYPE_RECENTDOCS: _normalize_recentdocs,
    ARTIFACT_TYPE_BAM: _normalize_bam,
    ARTIFACT_TYPE_MUICACHE: _normalize_muicache,
    ARTIFACT_TYPE_RUNMRU: _normalize_runmru,
    ARTIFACT_TYPE_WORDWHEELQUERY: _normalize_word_wheel_query,
    ARTIFACT_TYPE_COMDLG32: _normalize_comdlg32,
    ARTIFACT_TYPE_INSTALLEDPROGRAMS: _normalize_installed_programs,
    ARTIFACT_TYPE_COMPUTERNAME: _normalize_computer_name,
    ARTIFACT_TYPE_TIMEZONE: _normalize_time_zone,
    ARTIFACT_TYPE_WINDOWSVERSION: _normalize_windows_version,
    ARTIFACT_TYPE_SHELLBAGS: _normalize_shellbags,
    ARTIFACT_TYPE_COMPAT_ASSISTANT_STORE: _normalize_compat_assistant_store,
    ARTIFACT_TYPE_FIREFOX_LAUNCHER: _normalize_firefox_launcher,
    ARTIFACT_TYPE_APP_SWITCHED: _normalize_app_switched,
    ARTIFACT_TYPE_TYPEDPATHS: _normalize_typed_paths,
    ARTIFACT_TYPE_LASTVISITEDPIDLMRU: _normalize_last_visited_pidl_mru,
    ARTIFACT_TYPE_USBSTOR: _normalize_usbstor,
    ARTIFACT_TYPE_USBDEVICES: _normalize_usb_devices,
    ARTIFACT_TYPE_MOUNTEDDEVICES: _normalize_mounted_devices,
    ARTIFACT_TYPE_MOUNTPOINTS2: _normalize_mountpoints2,
    ARTIFACT_TYPE_EMDMGMT: _normalize_emdmgmt,
    ARTIFACT_TYPE_PORTABLEDEVICES: _normalize_portable_devices,
    ARTIFACT_TYPE_NETWORK_PROFILE: _normalize_network_profile,
    ARTIFACT_TYPE_NETWORK_INTERFACE: _normalize_network_interface,
    ARTIFACT_TYPE_RUNKEY: _normalize_run_key,
    ARTIFACT_TYPE_SERVICE: _normalize_service,
    ARTIFACT_TYPE_PROXY_SETTINGS: _normalize_proxy_settings,
}


def normalize_entry(artifact_type: str, entry: dict, source_hive: str) -> Artifact:
    """Convert one raw regipy entry into the shared core.schema.Artifact shape.

    `source_hive` is the path (or label) of the hive the entry came from —
    it is recorded verbatim in Artifact.source for traceability back to the
    acquired evidence file, independent of the chain-of-custody log.

    confidence/confidence_reason/category are looked up once here, by
    artifact_type, from constants.py's maps — the single source of truth as
    of Phase 0 (see that module's own docstring on why this replaced both
    per-type description prose and report.py's separate map).
    """
    try:
        normalizer = _NORMALIZERS[artifact_type]
    except KeyError as exc:
        raise ValueError(f"Unknown artifact_type: {artifact_type!r}") from exc

    description, timestamp = normalizer(entry)
    timestamp = _clean_timestamp(timestamp)

    return Artifact(
        module=MODULE_NAME,
        artifact_type=artifact_type,
        source=str(source_hive),
        description=description,
        sha256=None,
        timestamp=timestamp,
        confidence=ARTIFACT_CONFIDENCE.get(artifact_type),
        confidence_reason=ARTIFACT_CONFIDENCE_REASON.get(artifact_type),
        category=ARTIFACT_CATEGORY.get(artifact_type, CATEGORY_TOR_DIRECT),
    )
