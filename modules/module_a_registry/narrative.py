"""Deterministic, rule-based plain-English narrative for Module A's report section.

Every sentence here comes from a fixed rule applied to already-computed findings -- no
LLM, no free-text generation -- so the same evidence always produces the same text, and
every sentence can be traced back to one specific rule. Wording is deliberately cautious:
"indicates"/"shows", never "proves" -- these are registry artifacts, not a direct
observation of browsing activity.

Two audiences, two vocabularies: `build_narrative()`'s top-level `key_finding`/`timeline`/
`reliability`/`not_determined` are written for a non-technical reader and never name a
registry artifact type, a hive, a SID, or a "run count"/"focus" counter -- everything that
needs one of those words lives in the `technical` sub-dict instead, which the report's
"Technical details" appendix renders. Several rules below exist in both a plain and a
technical flavor for exactly this reason (e.g. describe_user_account vs.
describe_user_account_plain); the technical flavor also carries the existing wording the
original (examiner-only) report used, so nothing already-audited silently changes meaning.

Intended as the template for Module B/C's own plain-English sections later: one small,
independently testable function per interpretation rule, composed by build_narrative()
into one ordered story. A module's report.py calls build_narrative() after it has already
computed its own correlation structures (here: component_timeline, linked_launches,
quiet_hive_notes from report.py) and folds the result into its build_context() output.
"""

from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from .constants import CATEGORY_TOR_DIRECT, parse_tor_installer_filename

# ---------------------------------------------------------------------------
# Glossary -- merged with other modules' glossaries by the root report.py.
# ---------------------------------------------------------------------------

GLOSSARY: dict[str, str] = {
    "UserAssist": (
        "A part of the Windows Registry that records programs started from the "
        "Explorer desktop or Start menu, including how many times and when."
    ),
    "Amcache": (
        "A Windows Registry file that records software Windows has seen installed or "
        "run, largely independent of whether that software is still present or was run "
        "recently."
    ),
    "ShimCache": (
        "Also called AppCompatCache — a Windows Registry cache of programs Windows has "
        "seen, for compatibility purposes. It shows a program was present, not "
        "necessarily that it was run."
    ),
    "BAM": (
        "Background Activity Moderator — a Windows Registry record, separate from "
        "UserAssist, of the last time a program actually ran."
    ),
    "registry hive": (
        "A file holding part of the Windows Registry's configuration data. TRANCE reads "
        "these files directly rather than the live Windows Registry."
    ),
    "NTUSER.DAT": (
        "The registry hive file holding one Windows user account's personal settings and "
        "activity history, including UserAssist."
    ),
    "UTC": (
        "Coordinated Universal Time — a single, location-independent time standard. "
        "TRANCE always records evidence timestamps in UTC so they don't depend on any "
        "computer's local clock setting."
    ),
    "\\Device\\HarddiskVolumeN": (
        "Windows' own internal name for the Nth storage volume it found — not the drive "
        "letter shown in File Explorer. TRANCE shows the matching drive letter when it "
        "can be inferred from another record of the same file; otherwise it is shown "
        "as-is, with a note that the letter could not be determined."
    ),
    "NetworkList": (
        "A part of the Windows Registry that records every network (Wi-Fi, wired, or "
        "mobile hotspot) this computer has ever connected to, including when it was "
        "first and last connected to."
    ),
    "SSID": ("The name of a Wi-Fi network, as it appears when choosing a network to join."),
    "gateway MAC address": (
        "A unique hardware identifier for the router a network connection went through — "
        "useful for telling apart two different networks that happen to share the same "
        "name."
    ),
    "DHCP lease": (
        "A temporary IP address assignment a network hands out to a device, valid for a "
        "limited time window (from when it was obtained until it expires)."
    ),
    "Run key": (
        "A part of the Windows Registry listing programs set to start automatically, "
        "either when any user signs in (machine-wide) or when a specific user signs in."
    ),
    "service": (
        "A Windows program registered to start automatically in the background, usually "
        "without any visible window, often starting with the computer itself rather than "
        "waiting for a user to sign in."
    ),
    "proxy": (
        "A configuration that tells a program to send its network traffic through "
        "another address first, rather than directly to its destination."
    ),
    "SOCKS port": (
        "The network port a program connects to in order to route its traffic through "
        "Tor. Tor Browser's own Tor process listens on port 9150 (or 9050 for a "
        "standalone Tor install); another program configured to use that port is routing "
        "its own traffic through Tor."
    ),
}

# ---------------------------------------------------------------------------
# Rule: download source
# ---------------------------------------------------------------------------

_DOWNLOAD_SOURCE_PATTERNS: tuple[tuple[str, str], ...] = (
    ("microsoftedgedownloads", "Microsoft Edge"),
    (r"\chrome\user data", "Google Chrome"),
    (r"\mozilla\firefox", "Mozilla Firefox"),
    (r"\downloads", "the user's Downloads folder"),
)


def describe_download_source(path: str | None) -> str | None:
    """Rule: a path under a known browser's download staging area, or the user's plain
    Downloads folder, names where the file was fetched from. Never guesses beyond these
    specific, known path shapes -- returns None rather than invent a source."""
    if not path:
        return None
    normalized = path.lower().replace("/", "\\")
    for pattern, source in _DOWNLOAD_SOURCE_PATTERNS:
        if pattern in normalized:
            return source
    return None


# Rule: Tor Browser installer filename -> version / architecture / portable is now
# shared with pipeline.py via constants.parse_tor_installer_filename (imported above),
# so both layers agree on what counts as the installer without duplicating the pattern.

# ---------------------------------------------------------------------------
# Rule: focus time ("time a window was in front of the user")
# ---------------------------------------------------------------------------


def describe_focus_duration(
    focus_time_ms: int | None, focus_count: int | None = None
) -> str | None:
    """Rule: focus_time_ms (like run_counter) is a *cumulative* counter UserAssist keeps
    for a component's entire history, not a single-visit duration -- summed across every
    time that window was ever in front of the user, with no per-occasion breakdown
    retained. Phrased as a running total once focus_count shows more than one occasion
    contributed to it; only a focus_count of 0/1 genuinely describes one single occasion.
    Rounded to whole seconds -- sub-second precision reads as false exactness to a
    non-technical reader. Deliberately avoids the word "focus" in its own output (kept
    only in this function's name/docstring) -- the plain-English report sections this
    feeds must not use that or other registry-internal terms."""
    if not focus_time_ms:
        return None
    seconds = round(focus_time_ms / 1000)
    if seconds <= 0:
        return None
    unit = "second" if seconds == 1 else "seconds"
    if focus_count and focus_count > 1:
        return (
            f"visible on screen for about {seconds} {unit} in total, across {focus_count} "
            "separate occasions"
        )
    return f"in front of the user for about {seconds} {unit}"


def describe_run0_with_focus(basename: str, focus_phrase: str) -> str:
    """Rule: run_count == 0 with focus data present means Windows recorded the window
    being used, but the run counter -- which only increments on a clean process exit --
    never logged a completed launch. Framed as an observation, not a launch; deliberately
    does not name UserAssist, which is a plain-English section."""
    return (
        f'Windows recorded the "{basename}" window being used ({focus_phrase}), but not '
        "as a completed launch — this can happen when a program is closed before it "
        "exits normally."
    )


# ---------------------------------------------------------------------------
# Rule: install location / drive
# ---------------------------------------------------------------------------

_DRIVE_RE = re.compile(r"^([A-Za-z]):\\")


def extract_drive_letter(path: str | None) -> str | None:
    """Pulls just the drive letter (e.g. "E") from a path that already names one
    directly -- shared by describe_install_location() below and report.py's Phase 2
    device correlation (_build_device_correlation()), which needs the letter *before*
    build_narrative() runs so it can look up a matching MountedDevices/USBSTOR record
    and hand the result back in as build_narrative()'s device_match parameter."""
    if not path:
        return None
    match = _DRIVE_RE.match(path.replace("/", "\\"))
    return match.group(1).upper() if match else None


def find_install_location_path(annotated_by_type: dict[str, list[dict]]) -> str | None:
    """Standalone re-run of the exact "install location" candidate selection
    build_narrative() does internally (first UserAssist finding with a run_count whose
    path ends .lnk, else the first non-installer one) -- exposed so report.py can resolve
    the Tor install's drive letter (via extract_drive_letter() above) for its device
    correlation before build_narrative() exists to hand it back out. Kept as a second,
    independent call rather than threading build_narrative()'s internal state out,
    since both compute the same deterministic answer from the same input."""
    user_assist = annotated_by_type.get("UserAssist", [])
    installer_finding = None
    for finding in user_assist:
        if parse_tor_installer_filename(finding.get("path")):
            installer_finding = finding
            break

    location_candidate = None
    for finding in user_assist:
        if not finding.get("run_count"):
            continue
        path = finding.get("path") or ""
        if path.lower().endswith(".lnk"):
            location_candidate = finding
            break
        if location_candidate is None and finding is not installer_finding:
            location_candidate = finding
    return location_candidate.get("path") if location_candidate else None


def describe_drive_device(
    drive_letter: str, device_info: dict | None, include_timing: bool = False
) -> str | None:
    """Shared wording for what's known about the physical device behind `drive_letter`,
    used by both describe_install_location()'s inline caveat and build_narrative()'s
    "Where Tor Browser ran from" section so the two can never disagree. Two cases this
    function has an opinion on (returns None for anything else -- see each caller for how
    they fill that gap, which differs by context):

    - Resolved (`device_info["name"]` set): names the specific device. `include_timing`
      (only passed True from the dedicated device_story section, never the shorter inline
      note) appends first/last-connected when available -- USBSTOR's own fields; a
      PortableDevices-only match has neither, so nothing is added for one of those.
    - Dynamic disk (`device_info["dynamic_disk"]` true): Windows does not support
      converting a removable USB disk to a dynamic disk, so finding a Dynamic Disk
      identifier on this drive is itself real, structural evidence it's a partition of an
      internal/fixed disk, not a USB stick -- a strong inference, phrased as such
      ("most likely"), not a certainty.
    """
    if not device_info:
        return None
    if device_info.get("name"):
        name = device_info["name"]
        serial = device_info.get("serial")
        serial_clause = f", serial {serial}" if serial else ""
        timing_clause = ""
        if include_timing:
            times = []
            if device_info.get("first_connected"):
                times.append(f"first connected {device_info['first_connected']}")
            if device_info.get("last_connected"):
                times.append(f"last connected {device_info['last_connected']}")
            if times:
                timing_clause = ", " + ", ".join(times)
        return (
            f"{drive_letter}: is a USB drive ({name}{serial_clause}) connected to this "
            f"computer{timing_clause} — files there may not remain on this machine."
        )
    if device_info.get("dynamic_disk"):
        return (
            f"{drive_letter}: is a volume on a Windows dynamic disk. Windows does not "
            "allow dynamic disks on removable USB drives, so "
            f"{drive_letter}: is most likely a partition of an internal (fixed) disk "
            "rather than a USB stick."
        )
    return None


def describe_install_location(
    path: str | None, device_info: dict | None = None
) -> tuple[str | None, str | None]:
    """Rule: the folder containing the executable is where it ran from; a drive letter
    other than C: gets an explicit removable/secondary-drive caveat, phrased as "may be"
    since a non-C: drive could just as easily be a second internal disk. Only works on a
    path that already names a drive letter directly -- a "\\Device\\HarddiskVolumeN\\..."
    path must be resolved to a letter by the caller first (see constants.infer_drive_letters);
    if it can't be, this simply has nothing to say about the drive.

    `device_info` (Phase 2, widened in the components-table-pollution fix round): when
    report.py's device correlation has directly tied this same drive letter to a physical
    USB device, or detected it's a Windows Dynamic Disk volume (Windows doesn't support
    those on removable media), the generic "may be a USB drive" hedge is replaced with
    the specific finding via the shared describe_drive_device() above (without
    first/last-connected timing -- that only appears in the dedicated device_story
    section). Falls back to exactly the pre-Phase-2 generic wording whenever neither
    applies (device_info is None, doesn't match this path's drive letter, or genuinely
    couldn't be resolved for some other reason) -- the literal "keep the current ... as
    fallback" instruction from the Phase 2 roadmap, still honored for this one case."""
    if not path:
        return None, None
    normalized = path.replace("/", "\\")
    folder = normalized.rsplit("\\", 1)[0] if "\\" in normalized else normalized

    match = _DRIVE_RE.match(normalized)
    note = None
    if match and match.group(1).upper() != "C":
        drive = match.group(1).upper()
        relevant_info = (
            device_info if device_info and device_info.get("drive_letter") == drive else None
        )
        note = describe_drive_device(drive, relevant_info)
        if note is None:
            note = (
                f"{drive}: is not the main system drive and may be a USB drive or a second "
                "disk — files there may not remain on this machine."
            )
    return folder, note


# ---------------------------------------------------------------------------
# Rule: Windows user account
# ---------------------------------------------------------------------------

_USER_PATH_RE = re.compile(r"\\users\\([^\\]+)\\", re.IGNORECASE)


def _username_from_profile_path(profile_path: str | None) -> str | None:
    if not profile_path:
        return None
    normalized = profile_path.replace("/", "\\").rstrip("\\")
    name = normalized.rsplit("\\", 1)[-1]
    return name or None


def _resolve_username(
    paths: list[str], bam_sid: str | None, profiles: list[dict] | None
) -> tuple[str | None, str]:
    """Shared resolution step for both the plain and technical account descriptions
    below. Returns (username, basis) where basis is "bam_profile" (the authoritative,
    SID-resolved identity), "path_guess" (a \\Users\\<name>\\ substring in the findings'
    own paths -- the only signal left when BAM/ProfileList aren't both available), or
    "unknown"."""
    if bam_sid and profiles:
        for profile in profiles:
            if profile.get("sid") == bam_sid:
                username = _username_from_profile_path(profile.get("path"))
                if username:
                    return username, "bam_profile"
    for path in paths:
        match = _USER_PATH_RE.search(path.replace("/", "\\"))
        if match:
            return match.group(1), "path_guess"
    return None, "unknown"


def describe_user_account(
    paths: list[str], bam_sid: str | None = None, profiles: list[dict] | None = None
) -> str:
    """Technical version (for examiners): names *how* the account was resolved -- BAM's
    `sid` field resolved through SOFTWARE's ProfileList (SID -> profile path) is an
    authoritative OS-level mapping and is called out explicitly when available; otherwise
    falls back to a \\Users\\<name>\\ substring in the findings' own paths, then states
    plainly when neither is available, rather than guessing."""
    username, basis = _resolve_username(paths, bam_sid, profiles)
    if basis == "bam_profile":
        return (
            f'This activity belongs to the Windows user account "{username}" '
            f"(resolved via BAM + ProfileList, SID {bam_sid})."
        )
    if basis == "path_guess":
        return f'This activity belongs to the Windows user account "{username}".'
    return "The specific Windows user account could not be determined from the available data."


def describe_user_account_plain(
    paths: list[str], bam_sid: str | None = None, profiles: list[dict] | None = None
) -> str:
    """Plain-English version: names the account as a short noun phrase for inline use in
    a sentence (e.g. "... opened by {this}."), with no mention of SID/BAM/ProfileList --
    those belong to describe_user_account()'s technical wording only."""
    username, _basis = _resolve_username(paths, bam_sid, profiles)
    if username:
        return f'the Windows account "{username}"'
    return "an unidentified Windows account"


# ---------------------------------------------------------------------------
# Rule: evidence strength / reliability
# ---------------------------------------------------------------------------


def describe_evidence_strength(component_timeline: list[dict]) -> str:
    """Technical version: a restatement of "how many independent sources agree",
    naming the sources, for the Technical details appendix. component_timeline is
    already sorted strongest-corroborated-first, so its first entry is the strongest
    claim available.

    Reads `execution_sources`, not the broader `seen_in` -- see report.py's
    EXECUTION_SOURCE_TYPES and _build_component_timeline() docstring for the decision
    this encodes: ShellBags only shows a folder was browsed in Explorer, not that
    anything in it was ever executed, so it must not count toward "N independent sources
    confirm execution" (MUICache, by contrast, is populated by the shell actually
    invoking a program, so it still counts here even though its own timestamp -- a
    shared registry-key last-write time -- is never used for timing). Falls back to
    `seen_in` when a component has no `execution_sources` key at all (an older
    hand-built fixture that predates this distinction) -- those were always built from
    execution-only source names anyway, so the fallback changes nothing for them."""
    if not component_timeline:
        return "Strength: no corroborating registry evidence was found."
    component = component_timeline[0]
    sources = component.get("execution_sources", component["seen_in"])
    if not sources:
        return (
            "Strength: no execution-confirming source (UserAssist/Amcache/ShimCache/BAM/"
            "MUICache) was found for the strongest-evidenced file -- only contextual "
            "records, such as folder-browsing history, which show something was "
            "accessed but not that it was executed."
        )
    if len(sources) >= 2:
        return (
            f"Strength: confirmed by {len(sources)} independent sources "
            f"({', '.join(sources)}) — stronger evidence than any single artifact type "
            "alone."
        )
    return (
        f"Strength: one source only ({sources[0]}). Solid evidence of use by this "
        "account, but not confirmed by a second, independent source."
    )


_NUMBER_WORDS = {2: "Two", 3: "Three", 4: "Four", 5: "Five"}


def describe_reliability(component_timeline: list[dict]) -> list[str]:
    """Plain-English version for the "How reliable is this?" section: how many separate
    Windows features agree, without naming any of them (that is technical detail, kept
    only in describe_evidence_strength() for the appendix), plus one short, generic
    sentence on why a feature can stay silent without repeating any specific hive's own
    caveat text here.

    Counts `execution_sources`, not `seen_in` -- same ShellBags-isn't-execution-evidence
    reasoning as describe_evidence_strength() above (see that function's docstring)."""
    if not component_timeline:
        return ["No Windows record of this activity was found, so there is nothing to rate here."]
    component = component_timeline[0]
    count = len(component.get("execution_sources", component["seen_in"]))
    if count >= 2:
        number = _NUMBER_WORDS.get(count, "Several")
        sentences = [
            (
                f"{number} separate Windows features independently recorded Tor "
                "Browser being opened by this account, which makes this strong evidence."
            )
        ]
    elif count == 1:
        sentences = [
            (
                "Only one Windows record shows this activity. That is solid evidence "
                "of use by this account, but it would be stronger if a second, "
                "independent record agreed."
            )
        ]
    else:
        sentences = [
            (
                "No Windows feature that confirms a program actually ran recorded this "
                "activity — only contextual records, such as folder-browsing history, "
                "which show something was accessed but not that it was executed."
            )
        ]
    sentences.append(
        "Some Windows features only keep the most recent record, or need a periodic scan "
        "that may not have run yet — that is why a real activity can still be missing "
        "from one or more of them."
    )
    return sentences


# ---------------------------------------------------------------------------
# Rule: what could not be determined
# ---------------------------------------------------------------------------


def describe_not_determined(
    install_timestamp: str | None,
    multiple_launches: bool,
    has_network_profiles: bool = False,
) -> list[str]:
    """Rule: a fixed, short bullet list of known gaps -- never phrased as "nothing more
    to find", since Module A only ever looks at the registry; Modules B/C cover the rest.

    `has_network_profiles` (Phase 3) gates the network-timing bullet below -- only worth
    stating when there was network data to be ambiguous about in the first place; defaults
    to False so existing callers/tests that predate Phase 3 are unaffected.
    """
    bullets: list[str] = []
    if not install_timestamp:
        bullets.append("The exact date Tor Browser was set up.")
    if multiple_launches:
        bullets.append(
            "The dates of earlier uses — Windows only keeps a record of the most recent one."
        )
    if has_network_profiles:
        bullets.append(
            "Which network was in use at the exact moment Tor Browser was opened — the "
            "registry only records when each network was first and last connected, not a "
            "connection history."
        )
    bullets.append(
        "What websites were visited or what was done inside Tor Browser — this comes "
        "only from the computer's registry; see this report's disk and memory sections "
        "for that."
    )
    return bullets


# ---------------------------------------------------------------------------
# Rule: nothing found
# ---------------------------------------------------------------------------


def describe_no_findings() -> list[str]:
    return [
        "No registry evidence that Tor Browser was run by this account was found.",
        (
            "This does not prove Tor Browser was never used — for example, a portable "
            "copy run from a USB drive, or a registry that was cleaned afterward, would "
            "leave little or nothing here."
        ),
    ]


# ---------------------------------------------------------------------------
# Time formatting
# ---------------------------------------------------------------------------


def format_dual_time(iso_timestamp: str, local_tz: str | None) -> str:
    """Technical version -- "3 Sep 2026 at 04:41:53 UTC (10:11 AM Asia/Colombo)". UTC is
    always the primary claim (what the registry actually stores); local time is
    parenthetical and only shown when a zone name was resolved/configured and it's a zone
    zoneinfo recognizes."""
    dt = datetime.fromisoformat(iso_timestamp)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    utc_str = f"{dt.day} {dt.strftime('%b %Y')} at {dt.strftime('%H:%M:%S')} UTC"

    if not local_tz:
        return utc_str
    try:
        local_dt = dt.astimezone(ZoneInfo(local_tz))
    except (ZoneInfoNotFoundError, ValueError):
        return utc_str
    local_str = local_dt.strftime("%I:%M %p").lstrip("0")
    return f"{utc_str} ({local_str} {local_tz})"


def format_dual_time_plain(iso_timestamp: str, local_tz: str | None) -> str:
    """Plain-English version -- "4 Oct 2026, 1:00 PM (07:30 UTC)". The reverse emphasis
    of format_dual_time(): local time leads (easier for a non-technical reader to relate
    to their own clock), UTC trails in brackets as the 24-hour reference time. Falls back
    to UTC-only, same 24-hour style, when no local zone is available."""
    dt = datetime.fromisoformat(iso_timestamp)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    utc_24h = dt.strftime("%H:%M")

    local_dt = None
    if local_tz:
        try:
            local_dt = dt.astimezone(ZoneInfo(local_tz))
        except (ZoneInfoNotFoundError, ValueError):
            local_dt = None

    if local_dt is None:
        return f"{dt.day} {dt.strftime('%b %Y')}, {utc_24h} UTC"
    local_str = local_dt.strftime("%I:%M %p").lstrip("0")
    return f"{local_dt.day} {local_dt.strftime('%b %Y')}, {local_str} ({utc_24h} UTC)"


# ---------------------------------------------------------------------------
# Rule: network context (Phase 3 of the Module A roadmap)
# ---------------------------------------------------------------------------


def local_systemtime_to_utc(local_iso: str, bias_minutes: int) -> str:
    """Converts a NetworkList DateCreated/DateLastConnected value (a naive local-time ISO
    string -- see extract_network_profiles()'s docstring) to UTC using the target
    machine's own recorded TimeZoneInformation Bias (Phase 0's TimeZone fact).

    Per the Windows TIME_ZONE_INFORMATION documentation (and confirmed against this
    project's own real evidence: Sri Lanka Standard Time, UTC+5:30, recorded Bias=-330):
    UTC = local time + Bias (minutes). Deliberately does NOT use ZoneInfo/the examiner's
    own `local_tz` display preference here -- that is a *different* time zone concept
    (see format_dual_time()'s docstring: the examiner's configured display zone, for
    showing an already-UTC timestamp conveniently) from the TARGET machine's own recorded
    Bias, which is what Windows actually used to produce this local SYSTEMTIME value in
    the first place."""
    dt = datetime.fromisoformat(local_iso)
    utc_dt = (dt + timedelta(minutes=bias_minutes)).replace(tzinfo=timezone.utc)
    return utc_dt.isoformat()


def find_latest_tor_use_iso(
    annotated_by_type: dict[str, list[dict]], component_timeline: list[dict]
) -> str | None:
    """Standalone re-run of build_narrative()'s own "most recently opened" computation
    (the latest UserAssist launch; BAM is not used, see BAM_SAME_USE_SECONDS) -- exposed so
    report.py can resolve the Tor launch instant for network
    correlation before build_narrative() exists to hand it back out. Same "second,
    independent call rather than threading internal state out" precedent as
    find_install_location_path()'s own docstring (both compute the same deterministic
    answer from the same input)."""
    user_assist = annotated_by_type.get("UserAssist", [])
    installer_finding = None
    for finding in user_assist:
        if parse_tor_installer_filename(finding.get("path")):
            installer_finding = finding
            break

    launch_candidates = [
        f
        for f in user_assist
        if f is not installer_finding and f.get("run_count") and f.get("timestamp")
    ]
    if not launch_candidates:
        return None
    latest = max(launch_candidates, key=lambda f: f["timestamp"])
    return latest["timestamp"]


_NETWORK_HISTORY_CAVEAT = (
    "Windows only keeps one first-connected and one last-connected time per network, not "
    "a connection history — so this cannot show whether the computer was connected to a "
    "particular network for the whole time Tor Browser was open, only the closest "
    "recorded connection before it was last opened."
)

_TIMEZONE_UNKNOWN_CAVEAT = (
    "The computer's own time zone setting could not be determined, so the times below are "
    "shown exactly as recorded — in the computer's own local time, not UTC — and have not "
    "been compared against the UTC-timestamped Tor Browser activity elsewhere in this "
    "report."
)


def _parse_utc(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        dt = datetime.fromisoformat(value)
    except ValueError:
        try:
            dt = datetime.strptime(value, "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
        except ValueError:
            return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def describe_closest_network_before_launch(
    profiles_utc: list[dict], latest_tor_use_iso: str | None
) -> str | None:
    """Rule: among every network profile with a decodable UTC last-connected time at or
    before the Tor launch instant, the one with the LATEST such time is "the most recent
    network connection recorded before Tor Browser was last opened" -- phrased exactly
    this way (never "while using Tor") per the project brief, since the registry only
    keeps one first/last connection per network, not a history (see
    _NETWORK_HISTORY_CAVEAT, stated once by the caller, not repeated here)."""
    if not latest_tor_use_iso:
        return None
    launch_dt = _parse_utc(latest_tor_use_iso)
    if launch_dt is None:
        return None

    candidates = [
        (p["_last_connected_utc_dt"], p)
        for p in profiles_utc
        if p.get("_last_connected_utc_dt") and p["_last_connected_utc_dt"] <= launch_dt
    ]
    if not candidates:
        return None
    _, profile = max(candidates, key=lambda c: c[0])
    name = profile.get("profile_name") or "an unnamed network"
    mac = profile.get("gateway_mac")
    mac_clause = f" (router {mac})" if mac else ""
    when = profile["_last_connected_utc_dt"].isoformat()
    return (
        f"The most recent network connection recorded before Tor Browser was last opened "
        f"was to {name}{mac_clause} at {when}."
    )


def describe_networks_created_same_day_as_launch(
    profiles_utc: list[dict], latest_tor_use_iso: str | None
) -> list[str]:
    """Rule: a network whose DateCreated (converted to UTC) falls on the same UTC
    calendar day as the most recent Tor launch is worth surfacing as context -- phrased as
    an observation ("was also set up"), never implying causation. A fixed, auditable
    same-calendar-day rule rather than an arbitrary time window."""
    if not latest_tor_use_iso:
        return []
    launch_dt = _parse_utc(latest_tor_use_iso)
    if launch_dt is None:
        return []
    sentences = []
    for profile in profiles_utc:
        created_dt = profile.get("_created_utc_dt")
        if created_dt and created_dt.date() == launch_dt.date():
            name = profile.get("profile_name") or "an unnamed network"
            sentences.append(
                f"The network {name} was also set up for the first time on the same day "
                "Tor Browser was last opened."
            )
    return sentences


def describe_dhcp_leases_covering_launch(
    interfaces: list[dict], latest_tor_use_iso: str | None
) -> list[str]:
    """Rule: if an interface's DHCP lease window [obtained, expires] contains the Tor
    launch instant, the interface held that IP address at the time Tor Browser was last
    opened -- stated as exactly that (an IP address held at the time), never as "this
    network was used for Tor traffic", which the lease data does not show."""
    if not latest_tor_use_iso:
        return []
    launch_dt = _parse_utc(latest_tor_use_iso)
    if launch_dt is None:
        return []
    sentences = []
    for interface in interfaces:
        obtained = _parse_utc(interface.get("lease_obtained_utc"))
        terminates = _parse_utc(interface.get("lease_terminates_utc"))
        if obtained and terminates and obtained <= launch_dt <= terminates:
            ip = interface.get("ip") or "an unknown address"
            sentences.append(
                f"The network interface held IP address {ip} from {obtained.isoformat()} "
                f"to {terminates.isoformat()}, which includes the moment Tor Browser was "
                "last opened. This shows the computer's own address during that window, "
                "not which network it was routed through or what it was used for."
            )
    return sentences


def build_network_narrative(
    profiles: list[dict],
    interfaces: list[dict],
    bias_minutes: int | None,
    latest_tor_use_iso: str | None,
) -> dict:
    """Composes Phase 3's "Network context at time of use" section. Returns
    {"correlation": [...], "caveats": [...]} -- empty lists (not a missing key) when there
    is nothing to say, so report.py can decide whether to render the section at all.

    When the system's time zone is unknown (bias_minutes is None), per the project brief
    this deliberately does NOT attempt any local-to-UTC comparison -- profiles are left
    with no "_*_utc_dt" fields, so describe_closest_network_before_launch() and
    describe_networks_created_same_day_as_launch() both correctly find nothing to say,
    and _TIMEZONE_UNKNOWN_CAVEAT explains why.
    """
    profiles_utc = []
    for profile in profiles:
        enriched = dict(profile)
        if bias_minutes is not None:
            if profile.get("created_local"):
                try:
                    enriched["_created_utc_dt"] = _parse_utc(
                        local_systemtime_to_utc(profile["created_local"], bias_minutes)
                    )
                except ValueError:
                    pass
            if profile.get("last_connected_local"):
                try:
                    enriched["_last_connected_utc_dt"] = _parse_utc(
                        local_systemtime_to_utc(profile["last_connected_local"], bias_minutes)
                    )
                except ValueError:
                    pass
        profiles_utc.append(enriched)

    correlation: list[str] = []
    caveats: list[str] = []

    if profiles_utc:
        caveats.append(_NETWORK_HISTORY_CAVEAT)
    if bias_minutes is None and profiles_utc:
        caveats.append(_TIMEZONE_UNKNOWN_CAVEAT)

    closest = describe_closest_network_before_launch(profiles_utc, latest_tor_use_iso)
    if closest:
        correlation.append(closest)
    correlation.extend(
        describe_networks_created_same_day_as_launch(profiles_utc, latest_tor_use_iso)
    )
    correlation.extend(describe_dhcp_leases_covering_launch(interfaces, latest_tor_use_iso))

    return {"correlation": correlation, "caveats": caveats}


# ---------------------------------------------------------------------------
# Rule: automatic start and proxy configuration (Phase 4 of the Module A roadmap)
# ---------------------------------------------------------------------------


def describe_run_key_autostart(run_keys: list[dict]) -> list[str]:
    """Rule: a RunKey finding only exists at all when it already references Tor (see
    constants.is_tor_related_entry() -- Module A never reports every autostart entry), so
    every one of these is evidence of deliberate, ongoing configuration, not a one-off
    session."""
    sentences = []
    for finding in run_keys:
        path = finding.get("path") or "A Tor-related program"
        value_name = finding.get("value_name")
        name_clause = f" (listed as {value_name!r})" if value_name else ""
        sentences.append(
            f"{path} is configured to start automatically when this user signs "
            f"in{name_clause} — indicating deliberate, ongoing use, not just a one-off "
            "session."
        )
    return sentences


def describe_service_autostart(services: list[dict]) -> list[str]:
    """Rule: same reasoning as describe_run_key_autostart() above, for a Windows service
    instead of a per-user Run key -- a service starts with the computer itself, often
    before any user signs in at all."""
    sentences = []
    for finding in services:
        path = finding.get("path") or "A Tor-related program"
        name = finding.get("service_name")
        name_clause = f" (service {name!r})" if name else ""
        sentences.append(
            f"{path} is installed as a Windows service{name_clause}, configured to "
            "start automatically with the computer — indicating deliberate, ongoing Tor "
            "use set up ahead of time, not just a one-off session."
        )
    return sentences


def describe_proxy_configuration(proxy_settings: list[dict]) -> list[str]:
    """Rule: a ProxySettings finding only exists when it's already confirmed enabled AND
    pointing at a Tor SOCKS port (constants.is_tor_proxy_config()) -- so every one of
    these means other programs were set up to route their own traffic through Tor, not
    merely that a proxy was available."""
    sentences = []
    for finding in proxy_settings:
        server = finding.get("proxy_server") or "a Tor SOCKS port"
        sentences.append(
            f"Other programs on this computer were configured to send their network "
            f"traffic through {server} — Tor's own proxy — meaning programs other than "
            "Tor Browser itself may have been set up to use Tor."
        )
    return sentences


def build_autostart_narrative(
    run_keys: list[dict], services: list[dict], proxy_settings: list[dict]
) -> list[str]:
    """Composes Phase 4's "Automatic start and proxy settings" section -- empty when
    there's nothing to say (no RunKey/Service/ProxySettings findings at all), so
    report.py/the template can skip rendering the section entirely rather than showing an
    empty one."""
    sentences: list[str] = []
    sentences.extend(describe_run_key_autostart(run_keys))
    sentences.extend(describe_service_autostart(services))
    sentences.extend(describe_proxy_configuration(proxy_settings))
    return sentences


# ---------------------------------------------------------------------------
# Rule: portable-install absence from InstalledPrograms (Phase 5 of the Module A roadmap)
# ---------------------------------------------------------------------------


def describe_portable_install_note(installed_programs_present: bool) -> str | None:
    """Rule: Tor Browser is normally run portable -- no installer, no entry in the
    Windows list of installed programs -- so InstalledPrograms having nothing for it is
    the EXPECTED case, not a gap in the evidence. Returns None when InstalledPrograms DID
    find something (a traditional, non-portable install) -- the note would be misleading
    there, since it did register."""
    if installed_programs_present:
        return None
    return (
        "Tor Browser is normally run as a portable app, with no installer and no entry "
        "in the Windows list of installed programs — its absence from that list is "
        "expected, not a sign anything is missing."
    )


# ---------------------------------------------------------------------------
# Rule: install date
# ---------------------------------------------------------------------------


def describe_install_date(
    install_timestamp: str | None, installer_seen: bool, local_tz: str | None
) -> str:
    """Technical version, for the appendix only: Amcache's own first-seen timestamp, if
    Amcache has a matching entry. When it doesn't, states the specific reason rather than
    a bare "not found": the installer's own UserAssist timestamp is never set when it
    never registers a completed run, and Amcache needs its own periodic compatibility
    scan to pick up a new binary, so a missing entry there doesn't mean the install never
    happened."""
    if install_timestamp:
        when = format_dual_time(install_timestamp, local_tz)
        return f"Tor Browser's install was first recorded by Windows on {when}."
    if installer_seen:
        return (
            "The exact installation date could not be determined: the installer's own "
            "UserAssist entry has no recorded run time (installers often don't register "
            "as a completed run), and Amcache — which would otherwise record an install "
            "date — has no matching entry, typically because its periodic scan hasn't "
            "run since."
        )
    return "The exact installation date could not be determined from the available registry data."


def describe_install_date_plain(
    install_timestamp: str | None, earliest_known_use: str | None, local_tz: str | None
) -> str:
    """Plain-English version: no Amcache/UserAssist internals -- either the exact date,
    or "not recorded, but before X" using the earliest use TRANCE does have a timestamp
    for, or a plain "not recorded" when neither is known."""
    if install_timestamp:
        when = format_dual_time_plain(install_timestamp, local_tz)
        return f"Tor Browser was set up on {when}."
    if earliest_known_use:
        when = format_dual_time_plain(earliest_known_use, local_tz)
        return f"The exact date it was set up is not recorded, but it was before {when}."
    return "The exact date it was set up is not recorded."


# ---------------------------------------------------------------------------
# Rule: agreement between independent sources on the same event
# ---------------------------------------------------------------------------


# UserAssist records a program being opened from the desktop or Start menu; BAM records the
# program's last activity, and is typically written when it stops. They describe the same
# start only when they are this close. A later BAM time was assumed to be "the same use,
# moments later" and promoted to "most recent use" -- on a real capture that put "last
# opened" at the moment the browser process exited, ten minutes after it was opened.
BAM_SAME_USE_SECONDS = 60


def _minutes_phrase(seconds: float) -> str:
    minutes = round(seconds / 60)
    if minutes < 1:
        return f"{round(seconds)} seconds"
    if minutes < 120:
        return f"{minutes} minute{'s' if minutes != 1 else ''}"
    hours = round(minutes / 60)
    return f"{hours} hours"


def describe_bam_after_launch(component: dict, local_tz: str | None) -> str | None:
    """Plain-English timeline sentence for a BAM time well after the latest launch: what it
    most likely means, without claiming more than the data shows."""
    userassist_dt = component.get("userassist_last_run")
    bam_dt = component.get("bam_last_run")
    if not userassist_dt or not bam_dt:
        return None
    gap = (bam_dt - userassist_dt).total_seconds()
    if gap <= BAM_SAME_USE_SECONDS:
        return None
    return (
        f"Windows last recorded Tor Browser running on {format_dual_time_plain(bam_dt.isoformat(), local_tz)}, "
        f"about {_minutes_phrase(gap)} after it was last opened. Windows usually records this "
        "when a program stops, so this most likely marks when that use ended; it could also be "
        "a later start that did not go through the desktop or Start menu."
    )


def describe_source_time_gap(component: dict, local_tz: str | None) -> str | None:
    """Technical version, for the appendix: when the strongest component has both a
    UserAssist and a BAM time and they differ, says what the difference means once, instead
    of leaving a reader to notice two different timestamps and wonder if they're two
    different events. Within BAM_SAME_USE_SECONDS they are the same start; a later BAM time
    most likely marks the end of that use; an earlier one means BAM has not been written
    since that launch -- expected while the program is still running."""
    userassist_dt = component.get("userassist_last_run")
    bam_dt = component.get("bam_last_run")
    if not userassist_dt or not bam_dt or userassist_dt == bam_dt:
        return None
    ua = format_dual_time(userassist_dt.isoformat(), local_tz)
    bam = format_dual_time(bam_dt.isoformat(), local_tz)
    gap = (bam_dt - userassist_dt).total_seconds()
    if abs(gap) <= BAM_SAME_USE_SECONDS:
        seconds = round(abs(gap))
        unit = "second" if seconds == 1 else "seconds"
        earlier, later = (
            (("UserAssist", ua), ("BAM", bam)) if gap > 0 else (("BAM", bam), ("UserAssist", ua))
        )
        return (
            f"{earlier[0]} recorded this at {earlier[1]}; {later[0]} recorded it at {later[1]} — a "
            f"gap of {seconds} {unit}. This is normal and refers to the same use, not two "
            "different events."
        )
    if gap > 0:
        return (
            f"UserAssist recorded the last opening at {ua}; BAM last recorded the program at "
            f"{bam}, {_minutes_phrase(gap)} later. BAM is usually written when a program stops, "
            "so the BAM time most likely marks the end of that use, not a second opening; it "
            "could also be a later start that did not go through the desktop or Start menu, "
            "which UserAssist does not record."
        )
    return (
        f"UserAssist recorded the last opening at {ua}; BAM's entry is older ({bam}). BAM is "
        "usually written when a program stops, so this is expected if Tor Browser was still "
        "running when the evidence was collected."
    )


def describe_last_use_summary(component: dict, local_tz: str | None) -> str | None:
    """Technical version: the time the report leads with everywhere as "last opened" (the
    plain-English key finding and timeline use the same UserAssist value), plus BAM's
    last-recorded-running time when it differs, each named with its source -- so a reader
    of the appendix never has to cross-check the headline against the detail tables."""
    userassist_dt = component.get("userassist_last_run")
    bam_dt = component.get("bam_last_run")
    parts = []
    if userassist_dt:
        parts.append(
            f"Most recently opened: {format_dual_time(userassist_dt.isoformat(), local_tz)}, "
            "recorded by UserAssist."
        )
    if bam_dt and bam_dt != userassist_dt:
        parts.append(
            f"Last recorded running: {format_dual_time(bam_dt.isoformat(), local_tz)}, "
            "recorded by BAM."
        )
    return " ".join(parts) or None


# ---------------------------------------------------------------------------
# Rule: the headline "key finding"
# ---------------------------------------------------------------------------


def build_key_finding(
    has_findings: bool,
    account_phrase: str,
    launch_count: int,
    latest_use_iso: str | None,
    local_tz: str | None,
) -> str:
    """One or two plain sentences answering "was Tor Browser used on this computer, by
    whom, and when was it last used" -- the first thing a non-technical reader sees.
    Uses the SAME launch_count/latest_use value the timeline's own launch sentence is
    built from (see build_narrative()), so the two can never disagree."""
    if not has_findings:
        return "No. No registry evidence was found that Tor Browser was used on this computer."
    if launch_count:
        times_phrase = "once" if launch_count == 1 else f"{launch_count} times"
        when_phrase = ""
        if latest_use_iso:
            when_phrase = (
                f" The most recent use was on {format_dual_time_plain(latest_use_iso, local_tz)}."
            )
        return (
            f"Yes. The evidence shows Tor Browser was installed and opened {times_phrase} "
            f"by {account_phrase}.{when_phrase}"
        )
    return (
        "Likely. The evidence shows Tor Browser was present on this computer under "
        f"{account_phrase}, but no completed launch was recorded."
    )


# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------


def _empty_result(lines: list[str]) -> dict:
    return {
        "empty": lines,
        "key_finding": lines[0] if lines else "",
        "timeline": [],
        "reliability": [],
        "not_determined": [],
        "technical": {"account": "", "strength": "", "install_date_detail": ""},
        "device_story": [],
    }


def build_narrative(
    annotated_by_type: dict[str, list[dict]],
    component_timeline: list[dict],
    linked_launches: list[dict],
    quiet_hive_notes: list[str],
    profiles: list[dict],
    local_tz: str | None,
    device_info: dict | None = None,
) -> dict:
    """Composes the rules above into the report's non-technical story (key_finding,
    timeline, reliability, not_determined -- no registry/hive/SID/run-count/focus
    terminology anywhere in these) plus a `technical` dict carrying the examiner-facing
    wording for the same facts (account resolution detail, source agreement/gap, exact
    install-date reasoning). Reuses component_timeline/linked_launches exactly as
    report.py already computed them for the technical tables -- no separate grouping
    logic here."""
    if not component_timeline:
        return _empty_result(describe_no_findings())

    user_assist = annotated_by_type.get("UserAssist", [])
    timeline: list[str] = []

    # Linked-launch timestamps, for quick membership checks below.
    linked_by_timestamp = {link["timestamp"]: link["paths"] for link in linked_launches}

    # -- installer / download / focus --------------------------------------------------
    installer_finding = None
    installer_info = None
    for finding in user_assist:
        path = finding.get("path")
        info = parse_tor_installer_filename(path)
        if info:
            installer_finding = finding
            installer_info = info
            break

    if installer_finding is not None:
        edition = " portable" if installer_info["portable"] else ""
        source = describe_download_source(installer_finding.get("path"))
        download_clause = f" and opened through {source}" if source else ""
        timeline.append(
            f"The Tor Browser {installer_info['version']}{edition} installer was "
            f"downloaded{download_clause}."
        )
        installer_focus_count = installer_finding.get("focus_count") or 0
        focus_phrase = describe_focus_duration(
            installer_finding.get("total_focus_time_ms"), installer_focus_count
        )
        if focus_phrase and not installer_finding.get("run_count"):
            if installer_focus_count > 1:
                timeline.append(
                    f"The installer window was {focus_phrase} — this is a running "
                    "total Windows keeps for this program, not a single-visit "
                    "duration, so it may be longer than just the most recent time "
                    "it was open."
                )
            else:
                timeline.append(
                    f"The installer window was {focus_phrase}, consistent with "
                    "clicking through the setup."
                )

    # -- install location ----------------------------------------------------------------
    location_candidate = None
    for finding in user_assist:
        if not finding.get("run_count"):
            continue
        path = finding.get("path") or ""
        if path.lower().endswith(".lnk"):
            location_candidate = finding
            break
        if location_candidate is None and finding is not installer_finding:
            location_candidate = finding
    if location_candidate is not None:
        folder, drive_note = describe_install_location(location_candidate.get("path"), device_info)
        if folder:
            sentence = f"Tor Browser was set up in {folder}."
            if drive_note:
                sentence += f" {drive_note}"
            timeline.append(sentence)

    # -- launches: UserAssist's run_counter is a *cumulative* per-component count, but
    # Windows only keeps the *latest* run's timestamp -- it never retains when any
    # earlier run happened. So "how many times" has to come from run_counter itself
    # (max across a linked shortcut+target pair, since they move together as one
    # logical launch), not from counting distinct timestamps -- that undercounts to 1
    # the moment the same component is launched more than once.
    launch_candidates = [
        f
        for f in user_assist
        if f is not installer_finding and f.get("run_count") and f.get("timestamp")
    ]
    launch_count = 0
    latest_use_iso: str | None = None
    launch_sentence: str | None = None
    if launch_candidates:
        launch_count = max(f["run_count"] for f in launch_candidates)
        latest = max(launch_candidates, key=lambda f: f["timestamp"])
        # "Opened" is the UserAssist launch time only: a later BAM time is usually the end
        # of that use, not a new opening (see BAM_SAME_USE_SECONDS); it gets its own
        # timeline sentence below. describe_last_use_summary() shows the same pair.
        latest_use_iso = latest["timestamp"]

        when = format_dual_time_plain(latest_use_iso, local_tz)
        latest_path = (latest.get("path") or "").lower()
        via_shortcut = latest_path.endswith(".lnk") or any(
            p.lower().endswith(".lnk") for p in linked_by_timestamp.get(latest["timestamp"], [])
        )
        shortcut_clause = ", using its shortcut" if via_shortcut else ""
        if launch_count <= 1:
            launch_sentence = f"Tor Browser was opened once, on {when}{shortcut_clause}."
        else:
            launch_sentence = (
                f"Tor Browser was opened {launch_count} times; the dates of earlier uses "
                f"were not recorded, but the most recent was on {when}{shortcut_clause}."
            )

    # -- install date (Amcache first-seen, if any entry exists for it) -- appended before
    # the launch sentence below so the timeline stays chronological (install, then use),
    # even though latest_use_iso (computed above) is needed for its "before X" fallback.
    amcache_timestamps = [
        f["timestamp"] for f in annotated_by_type.get("Amcache", []) if f.get("timestamp")
    ]
    install_timestamp = min(amcache_timestamps) if amcache_timestamps else None
    timeline.append(describe_install_date_plain(install_timestamp, latest_use_iso, local_tz))

    # -- ShellBags folder-access events, interleaved chronologically with the launch
    # sentence (both carry real timestamps) -- everything else in `timeline` keeps its
    # existing fixed logical position; only ShellBags-vs-launch ordering is genuinely
    # time-sorted. ShellBags findings are already tor-direct and is_tor_related()-filtered
    # (folder paths containing a Tor marker), so every one present is relevant -- no
    # further filtering needed here.
    #
    # Wording note: a ShellBags entry's timestamp is the BagMRU registry key's own
    # last-write time (shared by every program/folder slot under that key), NOT the
    # folder's own filesystem access time -- that field exists in the raw plugin data but
    # is never surfaced past extraction. A key-write isn't guaranteed to mean "freshly
    # visited at this exact instant" (e.g. Explorer can update a key for other reasons),
    # so this says "Explorer recorded ... (last updated X)", not "the user opened ... on
    # X" -- the stronger claim the raw data doesn't actually support.
    dated_events: list[tuple[datetime, str]] = []
    if launch_sentence and latest_use_iso:
        dated_events.append((datetime.fromisoformat(latest_use_iso), launch_sentence))
        strongest_component = component_timeline[0] if component_timeline else {}
        bam_sentence = describe_bam_after_launch(strongest_component, local_tz)
        if bam_sentence:
            dated_events.append((strongest_component["bam_last_run"], bam_sentence))
    for finding in annotated_by_type.get("ShellBags", []):
        sb_path = finding.get("path")
        sb_timestamp = finding.get("timestamp")
        if not sb_path or not sb_timestamp:
            continue
        when = format_dual_time_plain(sb_timestamp, local_tz)
        dated_events.append(
            (
                datetime.fromisoformat(sb_timestamp),
                f"Explorer recorded the folder {sb_path} (last updated {when}).",
            )
        )
    dated_events.sort(key=lambda event: event[0])
    timeline.extend(sentence for _, sentence in dated_events)

    # -- non-installer run_count==0-with-focus entries (e.g. a different unlaunched app) -
    for finding in user_assist:
        if finding is installer_finding or finding.get("run_count"):
            continue
        focus_phrase = describe_focus_duration(
            finding.get("total_focus_time_ms"), finding.get("focus_count")
        )
        if not focus_phrase:
            continue
        path = finding.get("path") or ""
        basename = path.replace("/", "\\").rsplit("\\", 1)[-1] or path
        timeline.append(describe_run0_with_focus(basename, focus_phrase))

    # Same category guard as report.py's _is_tor_direct(): a context-category finding
    # (USB/MountedDevices/ComputerName/etc.) must never feed account resolution's
    # \Users\<name>\ path scan -- defensive scoping alongside Fix 1's component-table fix,
    # even though no context-category path has ever actually matched that pattern in
    # practice (confirmed against real evidence).
    all_paths = [f.get("path") for f in user_assist if f.get("path")]
    for findings in annotated_by_type.values():
        all_paths.extend(
            f.get("path")
            for f in findings
            if f.get("path") and f.get("category", CATEGORY_TOR_DIRECT) == CATEGORY_TOR_DIRECT
        )
    all_paths = [p for p in all_paths if p]

    bam_sid = next((f.get("sid") for f in annotated_by_type.get("BAM", []) if f.get("sid")), None)

    # -- "Where Tor Browser ran from": resolve the install drive to a physical device
    # when possible, else state so plainly and list possible candidates (item 2's own
    # wording) -- never alongside a resolved or dynamic-disk result. Shares
    # describe_drive_device() with describe_install_location()'s inline caveat above so
    # the two can never disagree; this section additionally shows first/last-connected
    # timing when available (include_timing=True) and the standalone "couldn't be
    # identified" + candidates text the shorter inline note has no room for.
    device_story: list[str] = []
    if location_candidate is not None:
        install_drive = extract_drive_letter(location_candidate.get("path"))
        if install_drive and install_drive != "C":
            relevant_info = (
                device_info
                if device_info and device_info.get("drive_letter") == install_drive
                else None
            )
            resolved_sentence = describe_drive_device(
                install_drive, relevant_info, include_timing=True
            )
            if resolved_sentence:
                device_story.append(resolved_sentence)
            else:
                device_story.append(
                    f"The device behind {install_drive}: could not be identified from the registry."
                )
                candidates = (relevant_info or {}).get("candidates") or []
                if candidates:
                    parts = []
                    for candidate in candidates:
                        name = candidate.get("name") or "an unidentified device"
                        serial = candidate.get("serial")
                        serial_clause = f" (serial {serial})" if serial else ""
                        last_connected = candidate.get("last_connected")
                        connected_clause = (
                            f", last connected {last_connected}" if last_connected else ""
                        )
                        parts.append(f"{name}{serial_clause}{connected_clause}")
                    device_story.append(
                        "Possible candidates connected to this computer: " + "; ".join(parts) + "."
                    )

    strongest = component_timeline[0]
    technical = {
        "account": describe_user_account(all_paths, bam_sid, profiles),
        "strength": describe_evidence_strength(component_timeline),
        "install_date_detail": describe_install_date(
            install_timestamp, installer_finding is not None, local_tz
        ),
        "last_use_summary": describe_last_use_summary(strongest, local_tz),
        "time_gap": describe_source_time_gap(strongest, local_tz),
        "install_drive_letter": (
            extract_drive_letter(location_candidate.get("path")) if location_candidate else None
        ),
    }

    return {
        "empty": [],
        "key_finding": build_key_finding(
            has_findings=True,
            account_phrase=describe_user_account_plain(all_paths, bam_sid, profiles),
            launch_count=launch_count,
            latest_use_iso=latest_use_iso,
            local_tz=local_tz,
        ),
        "timeline": timeline,
        "reliability": describe_reliability(component_timeline),
        "not_determined": describe_not_determined(
            install_timestamp,
            launch_count > 1,
            has_network_profiles=bool(annotated_by_type.get("NetworkProfile")),
        ),
        "technical": technical,
        "account_sid": bam_sid,
        "device_story": device_story,
    }
