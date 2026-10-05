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
from datetime import datetime, timezone
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from .constants import parse_tor_installer_filename

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


def describe_install_location(path: str | None) -> tuple[str | None, str | None]:
    """Rule: the folder containing the executable is where it ran from; a drive letter
    other than C: gets an explicit removable/secondary-drive caveat, phrased as "may be"
    since a non-C: drive could just as easily be a second internal disk. Only works on a
    path that already names a drive letter directly -- a "\\Device\\HarddiskVolumeN\\..."
    path must be resolved to a letter by the caller first (see constants.infer_drive_letters);
    if it can't be, this simply has nothing to say about the drive."""
    if not path:
        return None, None
    normalized = path.replace("/", "\\")
    folder = normalized.rsplit("\\", 1)[0] if "\\" in normalized else normalized

    match = _DRIVE_RE.match(normalized)
    note = None
    if match and match.group(1).upper() != "C":
        drive = match.group(1).upper()
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
    claim available."""
    if not component_timeline:
        return "Strength: no corroborating registry evidence was found."
    sources = component_timeline[0]["seen_in"]
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
    caveat text here."""
    if not component_timeline:
        return ["No Windows record of this activity was found, so there is nothing to rate here."]
    count = len(component_timeline[0]["seen_in"])
    if count >= 2:
        number = _NUMBER_WORDS.get(count, "Several")
        sentences = [
            (
                f"{number} separate Windows features independently recorded Tor "
                "Browser being opened by this account, which makes this strong evidence."
            )
        ]
    else:
        sentences = [
            (
                "Only one Windows record shows this activity. That is solid evidence "
                "of use by this account, but it would be stronger if a second, "
                "independent record agreed."
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


def describe_not_determined(install_timestamp: str | None, multiple_launches: bool) -> list[str]:
    """Rule: a fixed, short bullet list of known gaps -- never phrased as "nothing more
    to find", since Module A only ever looks at the registry; Modules B/C cover the rest.
    """
    bullets: list[str] = []
    if not install_timestamp:
        bullets.append("The exact date Tor Browser was set up.")
    if multiple_launches:
        bullets.append(
            "The dates of earlier uses — Windows only keeps a record of the most recent one."
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


def describe_source_time_gap(component: dict, local_tz: str | None) -> str | None:
    """Technical version, for the appendix: when the strongest component has both a
    UserAssist and a BAM last-run time and they differ, explains the gap once instead of
    leaving a reader to notice two slightly different timestamps in the table and wonder
    if they're two different events. A gap here is expected -- UserAssist records the
    desktop click, BAM the OS's own view of the program actually running moments later."""
    userassist_dt = component.get("userassist_last_run")
    bam_dt = component.get("bam_last_run")
    if not userassist_dt or not bam_dt or userassist_dt == bam_dt:
        return None
    if userassist_dt < bam_dt:
        earlier_label, earlier_dt, later_label, later_dt = (
            "UserAssist",
            userassist_dt,
            "BAM",
            bam_dt,
        )
    else:
        earlier_label, earlier_dt, later_label, later_dt = (
            "BAM",
            bam_dt,
            "UserAssist",
            userassist_dt,
        )
    gap_seconds = round((later_dt - earlier_dt).total_seconds())
    unit = "second" if gap_seconds == 1 else "seconds"
    return (
        f"{earlier_label} recorded this at {format_dual_time(earlier_dt.isoformat(), local_tz)}; "
        f"{later_label} recorded it at {format_dual_time(later_dt.isoformat(), local_tz)} — a "
        f"gap of {gap_seconds} {unit}. This is normal and refers to the same use, not two "
        "different events."
    )


def describe_last_use_summary(component: dict, local_tz: str | None) -> str | None:
    """Technical version: states the single most-recent-use time this report leads with
    everywhere (the plain-English key finding/timeline use the same underlying value, via
    format_dual_time_plain) together with which source it came from, so a reader of the
    appendix never has to cross-check that the headline time matches the detail tables."""
    candidates = []
    if component.get("userassist_last_run"):
        candidates.append(("UserAssist", component["userassist_last_run"]))
    if component.get("bam_last_run"):
        candidates.append(("BAM", component["bam_last_run"]))
    if not candidates:
        return None
    label, dt = max(candidates, key=lambda c: c[1])
    return (
        f"Most recent recorded use: {format_dual_time(dt.isoformat(), local_tz)}, "
        f"recorded by {label}."
    )


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
    }


def build_narrative(
    annotated_by_type: dict[str, list[dict]],
    component_timeline: list[dict],
    linked_launches: list[dict],
    quiet_hive_notes: list[str],
    profiles: list[dict],
    local_tz: str | None,
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
        folder, drive_note = describe_install_location(location_candidate.get("path"))
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
        latest_use_iso = latest["timestamp"]
        # The report's single "most recent use" also considers the strongest component's
        # BAM-recorded time (component_timeline is already strongest-first) -- the same
        # pair of numbers the technical appendix's describe_last_use_summary() shows, so
        # the plain-English headline and the technical detail can never disagree.
        bam_dt = component_timeline[0].get("bam_last_run") if component_timeline else None
        if bam_dt:
            latest_ua_dt = datetime.fromisoformat(latest_use_iso)
            if bam_dt > latest_ua_dt:
                latest_use_iso = bam_dt.isoformat()

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

    if launch_sentence:
        timeline.append(launch_sentence)

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

    all_paths = [f.get("path") for f in user_assist if f.get("path")]
    for findings in annotated_by_type.values():
        all_paths.extend(f.get("path") for f in findings if f.get("path"))
    all_paths = [p for p in all_paths if p]

    bam_sid = next((f.get("sid") for f in annotated_by_type.get("BAM", []) if f.get("sid")), None)

    strongest = component_timeline[0]
    technical = {
        "account": describe_user_account(all_paths, bam_sid, profiles),
        "strength": describe_evidence_strength(component_timeline),
        "install_date_detail": describe_install_date(
            install_timestamp, installer_finding is not None, local_tz
        ),
        "last_use_summary": describe_last_use_summary(strongest, local_tz),
        "time_gap": describe_source_time_gap(strongest, local_tz),
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
        "not_determined": describe_not_determined(install_timestamp, launch_count > 1),
        "technical": technical,
        "account_sid": bam_sid,
    }
