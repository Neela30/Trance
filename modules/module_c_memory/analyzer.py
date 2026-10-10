"""Offline, target-anchored analysis of a firefox.exe memory dump (.bin) produced by dumper.py."""

from __future__ import annotations

import argparse
import bisect
import html
import json
import os
import re
import sys
from collections import Counter
from collections.abc import Iterator
from concurrent.futures import ProcessPoolExecutor
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import parse_qsl

from core.exceptions import IntegrityError, ParsingError
from core.hashing import hash_file
from core.schema import Artifact

CHUNK_SIZE = 8 * 1024 * 1024
OVERLAP = 4096
DEFAULT_MIN_LEN = 6
SAMPLE_CAP = 20
SUGGESTION_MIN_HITS = 3
# A full-memory image carries every process's memory, not just one browser's -- Tor
# Browser's own bundled default services (search engine, connectivity checks) rack up
# more incidental hits there than in a single-process dump simply because there's more
# total scanned content, not because they're more significant. Same reasoning as
# SOURCE_TYPE_RECORD_CAPS below: same detection logic, source-type-scaled threshold for
# what counts as worth flagging.
SOURCE_TYPE_SUGGESTION_MIN_HITS = {
    "process": SUGGESTION_MIN_HITS,
    "full-memory": 6,
}
# Past process-dump scale (whole-system RAM images, pagefiles), an unbounded
# per-category list is the memory risk, not iter_strings() itself — cap each
# and record that it happened rather than let analyze() OOM silently.
MAX_RECORDS_PER_TYPE = 50_000
# A full-memory image carries every process's strings, not just one browser's, so the
# same per-category cap that's generous for a single process dump truncates far sooner
# on a whole-RAM image — raise it for that source type. Same extraction/regex logic
# either way; this only changes when append_capped() starts dropping records.
SOURCE_TYPE_RECORD_CAPS = {
    "process": MAX_RECORDS_PER_TYPE,
    "full-memory": 200_000,
}
DEFAULT_SOURCE_TYPE = "process"

# The scan is split into independent segments that run in separate processes. A segment
# reads SEGMENT_LOOKAHEAD bytes past its end so a login pair or page title that starts
# inside it is completed (TITLE_LINK_WINDOW is the longest look-ahead anything needs).
SEGMENT_LOOKAHEAD = 65536
SEGMENT_MIN_SIZE = 4 * CHUNK_SIZE  # 32 MiB: below this a segment isn't worth a process
SEGMENT_MAX_SIZE = 32 * CHUNK_SIZE  # 256 MiB: bounds one segment's partial results
PARALLEL_MIN_BYTES = 8 * CHUNK_SIZE  # 64 MiB: smaller dumps are scanned in-process
MAX_WORKERS = 8

# Proximity anchoring. A hit that carries no host of its own (a login pair, a form body)
# is attributed to the target when a string that does mention the target host/onion sits
# this close to it in the dump. Measured on a real full-RAM capture of a scripted session:
# the password sat 352 bytes, the username 432 and a posted form 768 bytes from the nearest
# target mention, so a couple of KB covers them without admitting page-sized neighbourhoods.
PROXIMITY_WINDOW = 2048
# Firefox keeps a form's field names as one-byte strings and the typed values as UTF-16, a
# few bytes apart ("username" <binary> "alice" ... "password" <binary> "hunter2"), so a
# field name and its value are never one extracted string. A value counts as belonging to
# the field name just before it when it starts within ADJACENT_GAP bytes of that name, and
# pairs less than ADJACENT_GROUP_GAP apart are one login form.
ADJACENT_GAP = 64
ADJACENT_GROUP_GAP = 256
# Page titles. A <title> in RAM could belong to any page of any process, and unlike a login
# form it sits far from the host string (measured: 0 of 10 real titles within 4 KiB of a
# target mention, while 135 unrelated titles turned up within 256 KiB), so proximity can't
# anchor it. What does: the page's own HTML links to paths -- "/search", "/static/style.css",
# "/library/..." -- and a page whose links include several paths this same analysis already
# saw requested from the target host is a page of the target site. Measured on the same
# capture: all 10 visited pages' titles, none of the 5 unvisited ones, and no foreign title.
TITLE_LINK_WINDOW = 16384
MIN_TITLE_LINKS = 3
TITLE_RE = re.compile(r"<title[^>]*>([^<]{1,200})</title>", re.IGNORECASE)
HREF_RE = re.compile(r"""\b(?:href|src)=["'](/[^"'#?\s]*)""", re.IGNORECASE)
CREDENTIAL_FIELD_NAMES = frozenset(
    {"username", "user", "uname", "login", "email", "password", "passwd", "pwd"}
)

# Trailing charset stops at , ^ | ] ) } as well as whitespace/quotes: Firefox's in-memory
# cache and principal keys wrap URLs in exactly those ("<host>,p,:http://…",
# "<url>^privateBrowsingId=1", "<host>:0|<hash>"), and letting them through turned one
# cache key per page into a fake "URL" finding.
URL_RE = re.compile(r"https?://[^\s\"'<>\\,^|\]\)\}]+")
# A scheme-less onion only counts as a navigation when it carries a /path; a bare
# domain is a mention (cache key, default list, search-engine query), not a visit.
ONION_RE = re.compile(
    r"(?P<host>[a-z2-7]{16,56}\.onion(?::\d{1,5})?)(?P<path>/[^\s\"'<>\\,^|\]\)\}]*)?",
    re.IGNORECASE,
)
ONION_DOMAIN_RE = re.compile(r"[a-z2-7]{16,56}\.onion", re.IGNORECASE)
COOKIE_RE = re.compile(r"\b(session|trance_user|trance_pref)=([^\s;\"'<>]+)")
SEARCH_QUERY_RE = re.compile(r"\?q=([^\s&\"'<>]+)")
# Lowercase-only and literal =/JSON-":" separators on purpose: keeps this from
# matching uppercase Windows env-var dumps (USERNAME=<os user>) and C++/JS
# identifiers (Pass::draw_indexed, LoginManager.sys.mjs) that share a substring
# but not the separator shape. Broadened past just username/password because
# real login forms commonly use user/uname/login/email/passwd/pwd instead.
CREDENTIAL_FIELDS = r"(username|user|uname|login|email|password|passwd|pwd)"
CREDENTIAL_RE = re.compile(r"\b" + CREDENTIAL_FIELDS + r"=([^\s&\"'<>]+)")
CREDENTIAL_JSON_RE = re.compile(r'"' + CREDENTIAL_FIELDS + r'"\s*:\s*"([^"\\]{1,200})"')
NOISY_COOKIE_RE = re.compile(
    r"\b(\w*(?:session|token|auth|cookie|csrf)\w*)=([^\s;\"'<>]{1,80})", re.IGNORECASE
)
# A posted form body: two or more name=value pairs joined by '&'. The lookbehind keeps it from
# starting inside a URL's query string ("...?a=1&b=2" is a link, not a submission).
FORM_BODY_RE = re.compile(
    r"(?<![\w?%./=&:-])(?:[A-Za-z][\w.\-\[\]]{0,39}=[^&\s\"'<>]{0,1000}&)+"
    r"[A-Za-z][\w.\-\[\]]{0,39}=[^&\s\"'<>]{0,1000}"
)
# Local download evidence: Firefox's in-memory download manager / session
# strings carry either a file:// URI or an absolute Windows path ending in a
# common downloaded-file extension.
FILE_URI_RE = re.compile(r"file:///[^\s\"'<>\\]+", re.IGNORECASE)
# ':' excluded from the path body (not just control/quote/angle-bracket/pipe chars): a
# real Windows path never contains a second ':' after the drive letter, and without this
# exclusion, memory holding the SAME path written twice back-to-back with no separator
# (seen in practice -- Explorer/MRU-style duplication) makes \b fail right after the
# first extension (word-char 'e' meeting word-char 'C' is not a boundary), so the regex
# backtrack-extends into the second copy and reports "...exeC:\...\...exe" as one bogus
# concatenated "path". Verified: this exact shape showed up 3x in a real capture.
DOWNLOAD_PATH_RE = re.compile(
    r"[A-Za-z]:\\(?:Users|Downloads)[^\x00-\x1f\"'<>|:]*?"
    r"\.(?:pdf|zip|rar|7z|exe|msi|docx?|xlsx?|pptx?|csv|txt|jpg|jpeg|png|gif|mp4|mp3|iso|dat)\b",
    re.IGNORECASE,
)
# Values that are Firefox's own printf-style format strings ("%p", "%lld."), near-empty
# leftovers ("a", "]"), or minified JS source that happens to contain "session=<code>"
# as a substring (destructuring/chained-assignment syntax, no whitespace) rather than
# real captured data -- these otherwise drown out genuine hits under the same exact-name
# regex. A real cookie/credential/session value never legitimately contains JS/code
# punctuation like parens or braces.
_NOISE_VALUE_RE = re.compile(r"^%|^.{1,2}$|[(){}]")


def _is_noise_value(value: str) -> bool:
    return bool(_NOISE_VALUE_RE.search(value))


# A hit under \Users\<name>\Downloads\ (Windows' actual save-to location,
# incl. the browser's own portable installer if the user downloaded it) is
# real user evidence. Anchored to the full Users/<name>/Downloads shape, not
# a bare "downloads" substring — Firefox's own UI resources use "downloads"
# as a path segment too (chrome/.../skin/.../downloads/downloads.svg is an
# icon, not a saved file) and would otherwise false-positive as high confidence.
_DOWNLOADS_DIR_RE = re.compile(r"users[\\/][^\\/]+[\\/]downloads[\\/]", re.IGNORECASE)


def _is_confirmed_download(value: str) -> bool:
    return bool(_DOWNLOADS_DIR_RE.search(value))


# Search-query / urlbar noise: Firefox's own template placeholders and
# origin-attribute-suffixed URLs (Firefox's internal principal serialization,
# e.g. "<url>^privateBrowsingId=1&firstPartyDomain=..." — never something a
# person typed or navigated to).
_TEMPLATE_NOISE_RE = re.compile(r"[{}]|searchTerms|TERMS%|^%s$")
ORIGIN_ATTR_RE = re.compile(r"\^privateBrowsingId|\^partitionKey|\^firstPartyDomain")


# Anything with "mozilla" in it that surfaced via a ?q= is Firefox's own baked-in
# telemetry/config, not a person typing.
_BROWSER_INTERNAL_RE = re.compile(r"mozilla", re.IGNORECASE)


# Public: report.py reuses this to dedupe search-term evidence for the same reason.
def is_timeline_noise(value: str) -> bool:
    if _is_noise_value(value) or _TEMPLATE_NOISE_RE.search(value) or ORIGIN_ATTR_RE.search(value):
        return True
    if _BROWSER_INTERNAL_RE.search(value):
        return True
    # "*?1", "\" and friends: nothing a person would type into a search box.
    return sum(ch.isalnum() for ch in value) < 3


# Automatic page-load requests. Real evidence that the page loaded, but not a user
# action — kept in the JSON, kept out of the site map and the activity sequence.
ASSET_EXTENSIONS = (
    ".css",
    ".js",
    ".map",
    ".ico",
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".svg",
    ".webp",
    ".woff",
    ".woff2",
    ".ttf",
)


def _is_asset_path(path: str) -> bool:
    return path.split("?", 1)[0].lower().endswith(ASSET_EXTENSIONS)


def _split_url(url: str) -> tuple[str, str]:
    """(host, path?query) for a schemed URL or a scheme-less onion match."""
    m = re.match(r"(?:https?://)?([^/?#]+)(.*)", url)
    if not m:
        return url.lower(), "/"
    host, rest = m.group(1).lower(), m.group(2)
    if rest and not rest.startswith("/"):
        rest = "/" + rest
    return host, rest or "/"


def _matches_target(host: str, targets: list[str]) -> bool:
    """Host-anchored, not substring: a search-engine URL that merely mentions the target
    in its query string is not a visit to the target."""
    for t in targets:
        if ":" in t:
            if host == t:
                return True
        elif host.split(":", 1)[0] == t:
            return True
    return False


def _ascii_pattern(min_len: int) -> re.Pattern[bytes]:
    return re.compile(rb"[\x20-\x7e]{%d,}" % min_len)


def _utf16le_pattern(min_len: int) -> re.Pattern[bytes]:
    return re.compile(rb"(?:[\x20-\x7e]\x00){%d,}" % min_len)


def iter_strings_ex(
    path: Path, min_len: int = DEFAULT_MIN_LEN, start: int = 0, end: int | None = None
) -> Iterator[tuple[int, str, int]]:
    """Yield (offset, string, length_in_bytes) for printable ASCII and UTF-16LE runs, in
    offset order, chunked to bound memory use.

    With start/end, scan only that byte range. Reading begins OVERLAP bytes before `start`
    so a run that began just before it is seen from its true start (callers own strings by
    their first byte), and a run that crosses `end` is read to its end by the caller
    passing an `end` that includes some look-ahead."""
    ascii_re = _ascii_pattern(min_len)
    utf16_re = _utf16le_pattern(min_len)
    # finditer() yields strictly increasing start offsets within a window, and the only
    # duplicates across windows are re-scans of the carried-over overlap region — so a
    # per-pattern high-water mark dedupes exactly like a seen-offsets set would, without
    # holding one Python int per match for the life of the scan (matters once "the dump"
    # is a multi-GB physical-RAM image or pagefile instead of a single process's memory).
    ascii_floor = -1
    utf16_floor = -1
    read_start = max(0, start - OVERLAP)
    with open(path, "rb") as f:
        f.seek(read_start)
        offset = read_start
        carry = b""
        while True:
            want = CHUNK_SIZE if end is None else min(CHUNK_SIZE, end - offset)
            if want <= 0:
                break
            chunk = f.read(want)
            if not chunk:
                break
            window = carry + chunk
            window_start = offset - len(carry)
            found: list[tuple[int, str, int]] = []
            for m in ascii_re.finditer(window):
                abs_off = window_start + m.start()
                if abs_off > ascii_floor:
                    ascii_floor = abs_off
                    found.append((abs_off, m.group().decode("ascii"), m.end() - m.start()))
            for m in utf16_re.finditer(window):
                abs_off = window_start + m.start()
                if abs_off > utf16_floor:
                    utf16_floor = abs_off
                    found.append(
                        (
                            abs_off,
                            m.group().decode("utf-16-le", errors="ignore"),
                            m.end() - m.start(),
                        )
                    )
            # Offset order across both encodings, so neighbouring strings (a field name
            # and its value are different encodings) are seen next to each other.
            found.sort(key=lambda t: t[0])
            yield from found
            offset += len(chunk)
            carry = window[-OVERLAP:] if len(window) > OVERLAP else window


def iter_strings(path: Path, min_len: int = DEFAULT_MIN_LEN) -> Iterator[tuple[int, str]]:
    """Yield (offset, string) for printable ASCII and UTF-16LE runs, in offset order."""
    for offset, string, _ in iter_strings_ex(path, min_len):
        yield offset, string


def _check_sidecar(dump_path: Path, actual_sha256: str) -> bool | None:
    """True if a <dump>.sha256 sidecar matches the computed hash, None if there is no sidecar,
    else raise."""
    sidecar = dump_path.with_name(dump_path.name + ".sha256")
    if not sidecar.exists():
        return None
    expected = sidecar.read_text().split()[0].strip().lower()
    if expected != actual_sha256:
        raise IntegrityError(
            f"Hash mismatch for {dump_path}: sidecar says {expected}, computed {actual_sha256}"
        )
    return True


def verify_integrity(dump_path: Path) -> bool | None:
    """Return True if a <dump>.sha256 sidecar matches, None if no sidecar exists, else raise."""
    sidecar = dump_path.with_name(dump_path.name + ".sha256")
    if not sidecar.exists():
        return None
    return _check_sidecar(dump_path, hash_file(dump_path))


def _is_plausible_credential_value(value: str) -> bool:
    return (
        3 <= len(value) <= 120
        and value not in CREDENTIAL_FIELD_NAMES
        and not _is_noise_value(value)
        and sum(ch.isalnum() for ch in value) >= 3
    )


_FLAG_WORDS = frozenset(
    {"true", "false", "null", "none", "undefined", "enabled", "disabled", "yes", "no", "default"}
)


# Firefox's origin attributes ("privateBrowsingId=1&firstPartyDomain=<site>&partitionKey=...")
# are '&'-joined and mention the site by construction, but are cache/principal keys, not forms.
_ORIGIN_ATTR_BODY_RE = re.compile(r"firstPartyDomain=|partitionKey=|userContextId=|BrowsingId=")


def _parse_form_body(body: str) -> list[tuple[str, str]]:
    """Decoded (name, value) pairs of a posted form body, or [] if it doesn't look like one."""
    if _ORIGIN_ATTR_BODY_RE.search(body):
        return []
    pairs = parse_qsl(body, keep_blank_values=True)
    if len(pairs) < 2 or any(_TEMPLATE_NOISE_RE.search(k) for k, _ in pairs):
        return []
    # Telemetry and config blobs are '&'-joined too; a real form carries at least one value
    # a person typed (some letters/digits) rather than only flags and numbers.
    if not any(
        sum(ch.isalpha() for ch in v) >= 3 and v.lower() not in _FLAG_WORDS for _, v in pairs
    ):
        return []
    return pairs


def _near_any(sorted_offsets: list[int], offset: int, window: int) -> bool:
    i = bisect.bisect_left(sorted_offsets, offset - window)
    return i < len(sorted_offsets) and sorted_offsets[i] <= offset + window


def _build_timeline(
    urls: list[dict],
    cookies: list[dict],
    search_queries: list[dict],
    credentials: list[dict],
    downloads: list[dict],
    username: str | None,
) -> list[dict]:
    """Merge already-extracted evidence into one offset-ordered candidate sequence.

    Offset is the only ordering signal a single memory snapshot gives us — see the
    'timeline.disclaimer' this feeds into. This only relabels/sorts evidence already
    surfaced elsewhere in the report; it invents nothing new.
    """
    first_offset: dict[str, int] = {}

    def earliest(value: str, offset_hex: str) -> None:
        off = int(offset_hex, 16)
        if value not in first_offset or off < first_offset[value]:
            first_offset[value] = off

    events: dict[str, dict] = {}

    def add_event(kind: str, label: str, value: str, offset_hex: str) -> None:
        earliest(f"{kind}:{value}", offset_hex)
        off = first_offset[f"{kind}:{value}"]
        key = f"{kind}:{value}"
        if key not in events or off < int(events[key]["offset"], 16):
            events[key] = {"offset": hex(off), "type": kind, "detail": label}

    # Key on host+path so the schemed and scheme-less forms of one visit collapse to one
    # event; show just the path when every hit is on the same host.
    hosts = {u["host"] for u in urls}
    for u in urls:
        if u["asset"]:
            continue
        canonical = u["host"] + u["path"]
        shown = u["path"] if len(hosts) == 1 else canonical
        add_event("page_visit", f"Visited {shown}", canonical, u["offset"])

    for c in cookies:
        if c["confidence"] != "high":
            continue
        add_event(
            "session",
            f"Session value observed: {c['name']}={c['value']}",
            f"{c['name']}={c['value']}",
            c["offset"],
        )

    for q in search_queries:
        if is_timeline_noise(q["value"]):
            continue
        label = f"Searched/typed: {q['value']}"
        if username and username.lower() in q["value"].lower():
            label += "  <-- matches --username"
        add_event("search", label, q["value"], q["offset"])

    for cr in credentials:
        if cr["confidence"] != "high":
            continue
        add_event(
            "credential",
            f"Credential submitted: {cr['field']}={cr['value']}",
            f"{cr['field']}={cr['value']}",
            cr["offset"],
        )

    for d in downloads:
        if d["confidence"] != "high":
            continue
        add_event("download", f"Downloaded: {d['value']}", d["value"], d["offset"])

    return sorted(events.values(), key=lambda e: int(e["offset"], 16))


def _scan_segment(
    dump_path: Path,
    start: int,
    end: int,
    *,
    min_len: int,
    targets: list[str],
    username: str | None,
    record_cap: int,
    require_host_anchor: bool,
    anchor_enabled: bool,
) -> dict:
    """String-carve [start, end) of the dump and return the raw, unmerged partial results.

    Pure function of its arguments, so segments can run in separate processes. A string is
    owned by the segment its first byte falls in; the read continues SEGMENT_LOOKAHEAD bytes
    past `end` only so that a login pair or page title that begins inside the segment is
    still completed.
    """
    urls: list[dict] = []
    cookies: list[dict] = []
    search_queries: list[dict] = []
    credentials: list[dict] = []
    downloads: list[dict] = []
    artifacts: list[dict] = []

    total_strings = 0
    unfiltered_url_count = 0
    unfiltered_url_sample: list[str] = []
    unfiltered_cookie_count = 0
    unfiltered_cookie_sample: list[str] = []
    onion_domain_hits: Counter[str] = Counter()
    truncated: dict[str, bool] = {}

    # Unlike URLs, a cookie/credential/search-query match carries no host of its own to
    # check against _matches_target() -- so on a single-process dump (already scoped to
    # one browser's memory) they're kept exactly as before. On a full-memory image,
    # every process's memory is in scope, and an exact-shape regex match (e.g. "user=...")
    # from an unrelated process is otherwise indistinguishable from a real one -- see
    # context.md's "why the 78 credentials are garbage" incident. The best proxy for
    # "this hit belongs to the target" without real per-process attribution (that's what
    # volatility_analyze.py's process extraction is for) is: does the *same extracted
    # string* also mention the target onion/host? Real form submissions and JS-rendered
    # page state commonly carry both in one contiguous run; unrelated processes' strings
    # essentially never do. Hits that fail this check aren't discarded -- they're kept
    # under "unanchored" for transparency, just excluded from "targeted"/key_findings.
    unanchored_counts = {"credentials": 0, "search_queries": 0}
    unanchored_samples: dict[str, list[str]] = {"credentials": [], "search_queries": []}

    # Proximity anchoring (see PROXIMITY_WINDOW): needs at least one target to anchor to.
    target_offsets: list[int] = []
    pending_field: tuple[str, int] | None = None
    adjacent_pairs: list[dict] = []
    form_candidates: list[dict] = []
    open_titles: list[dict] = []
    title_candidates: list[dict] = []

    def record_unanchored(category: str, value: str) -> None:
        unanchored_counts[category] += 1
        sample = unanchored_samples[category]
        if len(sample) < SAMPLE_CAP:
            sample.append(value)

    def append_capped(items: list[dict], item: dict, type_name: str) -> None:
        if len(items) >= record_cap:
            truncated[type_name] = True
            return
        items.append(item)

    def record_artifact(artifact_type: str, offset: int, description: str) -> None:
        append_capped(
            artifacts,
            asdict(
                Artifact(
                    module="module_c_memory",
                    artifact_type=artifact_type,
                    source=f"offset {hex(offset)}",
                    description=description,
                )
            ),
            "artifacts",
        )

    for offset, s, nbytes in iter_strings_ex(
        dump_path, min_len=min_len, start=start, end=end + SEGMENT_LOOKAHEAD
    ):
        if offset < start:
            continue  # owned by the previous segment
        owned = offset < end
        if owned:
            total_strings += 1
        s_low = s.lower()
        # Every pattern below needs some literal text to match at all, so checking for it
        # first skips running ~10 regexes over the millions of strings (per GB) that
        # contain none of it. Exactly equivalent: a gate is only false when the regex can't match.
        has_eq = "=" in s
        has_scheme = "://" in s
        has_onion = ".onion" in s_low
        mentions_target = bool(targets) and any(t in s_low for t in targets)
        s_matches_target = require_host_anchor and mentions_target
        if owned and mentions_target:
            target_offsets.append(offset)

        if anchor_enabled:
            if s in CREDENTIAL_FIELD_NAMES:
                # Past this segment's end a field name starts a pair the next segment owns.
                pending_field = (s, offset + nbytes) if owned else None
            elif pending_field is not None:
                gap = offset - pending_field[1]
                if 0 <= gap <= ADJACENT_GAP and _is_plausible_credential_value(s):
                    adjacent_pairs.append({"offset": offset, "field": pending_field[0], "value": s})
                    pending_field = None
                elif gap > ADJACENT_GAP:
                    pending_field = None

        if not owned:
            # Past this segment's end: only finish what began inside it (a field name's
            # value, a title's links); anything new here belongs to the next segment.
            if anchor_enabled and open_titles and ("href=" in s or "src=" in s):
                page_links = set(HREF_RE.findall(s))
                for pending in open_titles:
                    if offset <= pending["end"]:
                        pending["links"] |= page_links
            continue

        if anchor_enabled and "&" in s:
            for m in FORM_BODY_RE.finditer(s):
                fields = _parse_form_body(m.group())
                if fields:
                    form_candidates.append({"offset": offset + m.start(), "fields": fields})

        if anchor_enabled:
            while open_titles and offset > open_titles[0]["end"]:
                done = open_titles.pop(0)
                if done["links"]:
                    title_candidates.append(done)
            if "<title" in s:
                for m in TITLE_RE.finditer(s):
                    open_titles.append(
                        {
                            "offset": offset + m.start(),
                            "end": offset + m.start() + TITLE_LINK_WINDOW,
                            "title": html.unescape(m.group(1)).strip(),
                            "links": set(),
                        }
                    )
            if open_titles and ("href=" in s or "src=" in s):
                page_links = set(HREF_RE.findall(s))
                if page_links:
                    for pending in open_titles:
                        pending["links"] |= page_links

        url_spans: list[tuple[int, int]] = []
        url_hits: list[tuple[int, str, str, str]] = []
        for m in URL_RE.finditer(s) if has_scheme else ():
            url_spans.append((m.start(), m.end()))
            url_host, path = _split_url(m.group())
            url_hits.append((m.start(), m.group(), url_host, path))
        for m in ONION_RE.finditer(s) if has_onion else ():
            # Inside a full URL it's already covered by that URL (or is a search engine
            # merely mentioning it); without a path it's a mention, not a visit.
            if not m.group("path") or any(a <= m.start() < b for a, b in url_spans):
                continue
            url_hits.append((m.start(), m.group(), m.group("host").lower(), m.group("path")))
        for hit_start, url, url_host, path in url_hits:
            match_offset = offset + hit_start
            unfiltered_url_count += 1
            if len(unfiltered_url_sample) < SAMPLE_CAP:
                unfiltered_url_sample.append(url)
            if targets and _matches_target(url_host, targets):
                append_capped(
                    urls,
                    {
                        "offset": hex(match_offset),
                        "value": url,
                        "host": url_host,
                        "path": path,
                        "asset": _is_asset_path(path),
                    },
                    "urls",
                )
                record_artifact("url", match_offset, url)
        for m in ONION_DOMAIN_RE.finditer(s) if has_onion else ():
            onion_domain_hits[m.group().lower()] += 1
            # Only the top 10 ever get reported (targeting_suggestions below); on a
            # whole-system image with many distinct onion-like mentions this dict is
            # the growth risk, so periodically drop everything but the leaders.
            if len(onion_domain_hits) > 10_000:
                onion_domain_hits = Counter(dict(onion_domain_hits.most_common(1_000)))

        for m in COOKIE_RE.finditer(s) if has_eq else ():
            # Not host-anchored, unlike credentials/search-queries below: a cookie lives
            # in Firefox's own cookie-jar structure, not co-located in memory with the
            # page/URL text that set it, so the same-string proximity check that works
            # for form submissions just drops real cookies here (verified: it silently
            # ate a real, high-confidence JWT session cookie in testing). COOKIE_RE's own
            # exact app-specific name match (session/trance_user/trance_pref, not a
            # generic field name) is already the precision this needs.
            name, value = m.group(1), m.group(2)
            match_offset = offset + m.start()
            confidence = "low" if _is_noise_value(value) else "high"
            append_capped(
                cookies,
                {
                    "offset": hex(match_offset),
                    "name": name,
                    "value": value,
                    "confidence": confidence,
                },
                "cookies",
            )
            record_artifact("cookie", match_offset, f"{name}={value}")
        for m in NOISY_COOKIE_RE.finditer(s) if has_eq else ():
            unfiltered_cookie_count += 1
            if len(unfiltered_cookie_sample) < SAMPLE_CAP:
                unfiltered_cookie_sample.append(f"{m.group(1)}={m.group(2)}")

        for m in SEARCH_QUERY_RE.finditer(s) if "?q=" in s else ():
            value = m.group(1)
            match_offset = offset + m.start()
            if require_host_anchor and not s_matches_target:
                record_unanchored("search_queries", value)
                continue
            matches_username = bool(username) and username.lower() in value.lower()
            append_capped(
                search_queries,
                {"offset": hex(match_offset), "value": value, "matches_username": matches_username},
                "search_queries",
            )
            record_artifact("search_query", match_offset, value)

        for m in CREDENTIAL_RE.finditer(s) if has_eq else ():
            field, value = m.group(1), m.group(2)
            match_offset = offset + m.start()
            if require_host_anchor and not s_matches_target:
                record_unanchored("credentials", f"{field}={value}")
                continue
            confidence = "low" if _is_noise_value(value) else "high"
            append_capped(
                credentials,
                {
                    "offset": hex(match_offset),
                    "field": field,
                    "value": value,
                    "shape": "form",
                    "confidence": confidence,
                },
                "credentials",
            )
            record_artifact("credential", match_offset, f"{field}={value}")
        for m in CREDENTIAL_JSON_RE.finditer(s) if '"' in s and ":" in s else ():
            field, value = m.group(1), m.group(2)
            match_offset = offset + m.start()
            if require_host_anchor and not s_matches_target:
                record_unanchored("credentials", f'"{field}":"{value}"')
                continue
            confidence = "low" if _is_noise_value(value) else "high"
            append_capped(
                credentials,
                {
                    "offset": hex(match_offset),
                    "field": field,
                    "value": value,
                    "shape": "json",
                    "confidence": confidence,
                },
                "credentials",
            )
            record_artifact("credential", match_offset, f'"{field}":"{value}"')

        for m in (list(FILE_URI_RE.finditer(s)) if "file:///" in s_low else []) + (
            list(DOWNLOAD_PATH_RE.finditer(s)) if ":\\" in s else []
        ):
            value = m.group()
            match_offset = offset + m.start()
            confidence = "high" if _is_confirmed_download(value) else "low"
            append_capped(
                downloads,
                {"offset": hex(match_offset), "value": value, "confidence": confidence},
                "downloads",
            )
            record_artifact("download", match_offset, value)

    title_candidates.extend(t for t in open_titles if t["links"])
    return {
        "urls": urls,
        "cookies": cookies,
        "search_queries": search_queries,
        "credentials": credentials,
        "downloads": downloads,
        "artifacts": artifacts,
        "total_strings": total_strings,
        "unfiltered_url_count": unfiltered_url_count,
        "unfiltered_url_sample": unfiltered_url_sample,
        "unfiltered_cookie_count": unfiltered_cookie_count,
        "unfiltered_cookie_sample": unfiltered_cookie_sample,
        "onion_domain_hits": onion_domain_hits,
        "truncated": truncated,
        "unanchored_counts": unanchored_counts,
        "unanchored_samples": unanchored_samples,
        "target_offsets": target_offsets,
        "adjacent_pairs": adjacent_pairs,
        "form_candidates": form_candidates,
        "title_candidates": title_candidates,
    }


def _resolve_workers(workers: int | None) -> int:
    if workers is None:
        env = os.environ.get("TRANCE_WORKERS", "").strip()
        workers = int(env) if env.isdigit() else min(os.cpu_count() or 1, MAX_WORKERS)
    return max(1, workers)


def _plan_segments(size: int, workers: int) -> list[tuple[int, int]]:
    """Split [0, size) into CHUNK_SIZE-aligned segments, about four per worker."""
    if workers <= 1 or size < PARALLEL_MIN_BYTES:
        return [(0, size)]
    per = -(-size // (workers * 4))
    per = -(-per // CHUNK_SIZE) * CHUNK_SIZE
    per = max(SEGMENT_MIN_SIZE, min(SEGMENT_MAX_SIZE, per))
    return [(start, min(start + per, size)) for start in range(0, size, per)]


def _run_segments(
    dump_path: Path, *, workers: int | None, scan_args: dict
) -> tuple[list[dict], str]:
    """Scan every segment (in a process pool when worthwhile) and hash the file once.

    Returns the partial results in offset order and the file's SHA-256. The hash runs as one
    more task beside the scans instead of being a separate pass over the file, and a sidecar
    mismatch stops the run as soon as the hash lands.
    """
    workers = _resolve_workers(workers)
    size = dump_path.stat().st_size
    segments = _plan_segments(size, workers)
    if workers <= 1 or len(segments) == 1:
        sha = hash_file(dump_path)
        _check_sidecar(dump_path, sha)  # fail before spending time on a tampered file
        return [_scan_segment(dump_path, a, b, **scan_args) for a, b in segments], sha
    pool = ProcessPoolExecutor(max_workers=min(workers, len(segments) + 1))
    try:
        hash_future = pool.submit(hash_file, dump_path)
        futures = [pool.submit(_scan_segment, dump_path, a, b, **scan_args) for a, b in segments]
        sha: str | None = None
        parts: list[dict] = []
        for future in futures:
            parts.append(future.result())
            if sha is None and hash_future.done():
                sha = hash_future.result()
                _check_sidecar(dump_path, sha)
        if sha is None:
            sha = hash_future.result()
    except BaseException:
        pool.shutdown(wait=False, cancel_futures=True)
        raise
    pool.shutdown()
    return parts, sha


def _merge_partials(parts: list[dict], record_cap: int) -> dict:
    """Combine segment partials exactly as one sequential pass would have produced them."""
    merged: dict = {
        k: []
        for k in (
            "urls",
            "cookies",
            "search_queries",
            "credentials",
            "downloads",
            "artifacts",
            "unfiltered_url_sample",
            "unfiltered_cookie_sample",
            "target_offsets",
            "adjacent_pairs",
            "form_candidates",
            "title_candidates",
        )
    }
    merged.update(
        total_strings=0,
        unfiltered_url_count=0,
        unfiltered_cookie_count=0,
        onion_domain_hits=Counter(),
        truncated={},
        unanchored_counts={"credentials": 0, "search_queries": 0},
        unanchored_samples={"credentials": [], "search_queries": []},
    )
    for part in parts:
        for key in (
            "urls",
            "cookies",
            "search_queries",
            "credentials",
            "downloads",
            "artifacts",
            "target_offsets",
            "adjacent_pairs",
            "form_candidates",
            "title_candidates",
        ):
            merged[key].extend(part[key])
        for key in ("total_strings", "unfiltered_url_count", "unfiltered_cookie_count"):
            merged[key] += part[key]
        merged["unfiltered_url_sample"].extend(part["unfiltered_url_sample"])
        merged["unfiltered_cookie_sample"].extend(part["unfiltered_cookie_sample"])
        merged["onion_domain_hits"].update(part["onion_domain_hits"])
        for key, flag in part["truncated"].items():
            merged["truncated"][key] = merged["truncated"].get(key, False) or flag
        for cat in ("credentials", "search_queries"):
            merged["unanchored_counts"][cat] += part["unanchored_counts"][cat]
            merged["unanchored_samples"][cat].extend(part["unanchored_samples"][cat])
    for key in ("urls", "cookies", "search_queries", "credentials", "downloads", "artifacts"):
        if len(merged[key]) > record_cap:
            merged[key] = merged[key][:record_cap]
            merged["truncated"][key] = True
    merged["unfiltered_url_sample"] = merged["unfiltered_url_sample"][:SAMPLE_CAP]
    merged["unfiltered_cookie_sample"] = merged["unfiltered_cookie_sample"][:SAMPLE_CAP]
    for cat in ("credentials", "search_queries"):
        merged["unanchored_samples"][cat] = merged["unanchored_samples"][cat][:SAMPLE_CAP]
    return merged


def analyze(
    dump_path: Path,
    onion: str | None,
    host: str | None,
    username: str | None,
    min_len: int = DEFAULT_MIN_LEN,
    source_type: str = DEFAULT_SOURCE_TYPE,
    workers: int | None = None,
) -> dict:
    if not dump_path.exists():
        raise ParsingError(f"Dump file not found: {dump_path}")

    integrity_verified: bool | None
    targets = [t.lower() for t in (onion, host) if t]
    record_cap = SOURCE_TYPE_RECORD_CAPS.get(source_type, MAX_RECORDS_PER_TYPE)
    # Unlike URLs, a cookie/credential/search-query match carries no host of its own to
    # check against _matches_target() -- so on a single-process dump (already scoped to
    # one browser's memory) they're kept exactly as before. On a full-memory image,
    # every process's memory is in scope, and an exact-shape regex match (e.g. "user=...")
    # from an unrelated process is otherwise indistinguishable from a real one -- see
    # context.md's "why the 78 credentials are garbage" incident. The best proxy for
    # "this hit belongs to the target" without real per-process attribution (that's what
    # volatility_analyze.py's process extraction is for) is: does the *same extracted
    # string* also mention the target onion/host? Real form submissions and JS-rendered
    # page state commonly carry both in one contiguous run; unrelated processes' strings
    # essentially never do. Hits that fail this check aren't discarded -- they're kept
    # under "unanchored" for transparency, just excluded from "targeted"/key_findings.
    require_host_anchor = source_type == "full-memory" and bool(targets)
    # Proximity anchoring (see PROXIMITY_WINDOW): needs at least one target to anchor to.
    anchor_enabled = bool(targets) or bool(username)

    parts, dump_sha256 = _run_segments(
        dump_path,
        workers=workers,
        scan_args={
            "min_len": min_len,
            "targets": targets,
            "username": username,
            "record_cap": record_cap,
            "require_host_anchor": require_host_anchor,
            "anchor_enabled": anchor_enabled,
        },
    )
    integrity_verified = _check_sidecar(dump_path, dump_sha256)
    merged = _merge_partials(parts, record_cap)
    urls = merged["urls"]
    cookies = merged["cookies"]
    search_queries = merged["search_queries"]
    credentials = merged["credentials"]
    downloads = merged["downloads"]
    artifacts = merged["artifacts"]
    total_strings = merged["total_strings"]
    unfiltered_url_count = merged["unfiltered_url_count"]
    unfiltered_url_sample = merged["unfiltered_url_sample"]
    unfiltered_cookie_count = merged["unfiltered_cookie_count"]
    unfiltered_cookie_sample = merged["unfiltered_cookie_sample"]
    onion_domain_hits = merged["onion_domain_hits"]
    truncated = merged["truncated"]
    unanchored_counts = merged["unanchored_counts"]
    unanchored_samples = merged["unanchored_samples"]
    target_offsets = merged["target_offsets"]
    adjacent_pairs = merged["adjacent_pairs"]
    form_candidates = merged["form_candidates"]
    title_candidates = merged["title_candidates"]

    def record_unanchored(category: str, value: str) -> None:
        unanchored_counts[category] += 1
        sample = unanchored_samples[category]
        if len(sample) < SAMPLE_CAP:
            sample.append(value)

    def append_capped(items: list[dict], item: dict, type_name: str) -> None:
        if len(items) >= record_cap:
            truncated[type_name] = True
            return
        items.append(item)

    def record_artifact(artifact_type: str, offset: int, description: str) -> None:
        append_capped(
            artifacts,
            asdict(
                Artifact(
                    module="module_c_memory",
                    artifact_type=artifact_type,
                    source=f"offset {hex(offset)}",
                    description=description,
                )
            ),
            "artifacts",
        )

    # A login form's name/value pairs are anchored as a group: by the target username
    # appearing as one of the values, or by a target mention within PROXIMITY_WINDOW.
    target_offsets.sort()
    adjacent_pairs.sort(key=lambda p: p["offset"])
    groups: list[list[dict]] = []
    for pair in adjacent_pairs:
        if groups and pair["offset"] - groups[-1][-1]["offset"] <= ADJACENT_GROUP_GAP:
            groups[-1].append(pair)
        else:
            groups.append([pair])
    for group in groups:
        anchored_by = None
        if username and any(username.lower() in p["value"].lower() for p in group):
            anchored_by = "username"
        elif any(_near_any(target_offsets, p["offset"], PROXIMITY_WINDOW) for p in group):
            anchored_by = "host"
        for p in group:
            if anchored_by is None:
                record_unanchored("credentials", f"{p['field']}={p['value']}")
                continue
            append_capped(
                credentials,
                {
                    "offset": hex(p["offset"]),
                    "field": p["field"],
                    "value": p["value"],
                    "shape": "adjacent",
                    "confidence": "high",
                    "anchored_by": anchored_by,
                },
                "credentials",
            )
            record_artifact("credential", p["offset"], f"{p['field']}={p['value']}")

    # Posted forms: anchored by the target username among the values or by a nearby target
    # mention. The same body is often in memory several times -- keep one, count the rest.
    form_submissions: list[dict] = []
    seen_forms: dict[tuple, dict] = {}
    for cand in sorted(form_candidates, key=lambda c: c["offset"]):
        anchored_by = None
        if username and any(username.lower() in v.lower() for _, v in cand["fields"]):
            anchored_by = "username"
        elif _near_any(target_offsets, cand["offset"], PROXIMITY_WINDOW):
            anchored_by = "host"
        if anchored_by is None:
            continue
        key = tuple(cand["fields"])
        if key in seen_forms:
            seen_forms[key]["occurrences"] += 1
            continue
        record = {
            "offset": hex(cand["offset"]),
            "fields": [{"name": k, "value": v} for k, v in cand["fields"]],
            "anchored_by": anchored_by,
            "occurrences": 1,
        }
        seen_forms[key] = record
        append_capped(form_submissions, record, "form_submissions")
        shown = "; ".join(f"{k}='{v}'" for k, v in cand["fields"])
        record_artifact("form_submission", cand["offset"], f"Form submission: {shown}")

    # Page titles: keep those whose page links to enough paths seen under the target host.
    known_paths = {u["path"].split("?", 1)[0] for u in urls} - {"/"}
    page_titles: list[dict] = []
    seen_titles: dict[str, dict] = {}
    for cand in sorted(title_candidates, key=lambda c: c["offset"]):
        shared = sorted(cand["links"] & known_paths)
        if len(shared) < MIN_TITLE_LINKS or not cand["title"]:
            continue
        if cand["title"] in seen_titles:
            seen_titles[cand["title"]]["occurrences"] += 1
            continue
        record = {
            "offset": hex(cand["offset"]),
            "title": cand["title"],
            "linked_target_paths": shared,
            "occurrences": 1,
        }
        seen_titles[cand["title"]] = record
        append_capped(page_titles, record, "page_titles")
        record_artifact(
            "page_title",
            cand["offset"],
            f"Page title '{cand['title']}' (HTML page linking to {len(shared)} paths seen on the target)",
        )

    # Tor Browser itself talks to a handful of bundled default onion services
    # (search engine, connectivity checks) whether or not the user does
    # anything — those show up here too and are expected background noise,
    # not evidence of user action. Capped and left unlabeled rather than
    # guessing which specific v3 addresses are "default" (those can rotate).
    suggestion_min_hits = SOURCE_TYPE_SUGGESTION_MIN_HITS.get(source_type, SUGGESTION_MIN_HITS)
    targeting_suggestions = [
        {"onion": domain, "hit_count": count}
        for domain, count in onion_domain_hits.most_common(10)
        if count >= suggestion_min_hits and not any(domain in t for t in targets)
    ]

    def _dedup_high_confidence(items: list[dict], value_key: str) -> list[dict]:
        seen: dict[str, dict] = {}
        for item in items:
            if item.get("confidence") != "high":
                continue
            key = f"{item.get('name') or item.get('field', '')}={item[value_key]}"
            if key not in seen:
                seen[key] = {**item, "occurrences": 1}
            else:
                seen[key]["occurrences"] += 1
        return sorted(seen.values(), key=lambda i: -i["occurrences"])

    key_cookies = _dedup_high_confidence(cookies, "value")
    key_credentials = _dedup_high_confidence(credentials, "value")
    key_downloads = sorted({d["value"] for d in downloads if d["confidence"] == "high"})

    timeline = _build_timeline(urls, cookies, search_queries, credentials, downloads, username)

    return {
        "dump": {
            "path": str(dump_path),
            "size_bytes": dump_path.stat().st_size,
            "sha256": dump_sha256,
            "integrity_verified": integrity_verified,
            "source_type": source_type,
        },
        "record_cap": record_cap,
        "suggestion_min_hits": suggestion_min_hits,
        "targeting": {"onion": onion, "host": host, "username": username},
        "targeting_suggestions": targeting_suggestions,
        "key_findings": {
            "note": "Deduplicated, high-confidence hits only — start here. Full detail incl. low-confidence "
            "noise is in 'targeted' below.",
            "session_cookies": key_cookies,
            "credentials": key_credentials,
            "downloads": key_downloads,
            "target_urls_seen": sorted({u["host"] + u["path"] for u in urls}),
        },
        "targeted": {
            "urls": urls,
            "cookies": cookies,
            "search_queries": search_queries,
            "credentials": credentials,
            "downloads": downloads,
            "form_submissions": form_submissions,
            "page_titles": page_titles,
        },
        "timeline": {
            "disclaimer": "Ordered by memory offset ONLY — not a verified chronological timeline. Physical "
            "memory layout has no guaranteed relationship to time (allocator reuse and region placement can "
            "put older or newer data anywhere in the address space). Treat as a candidate sequence for "
            "investigator review, not proven fact — cross-reference real timestamped sources (browser "
            "history/places.sqlite, filesystem MACB times) before relying on the order.",
            "events": timeline,
        },
        "unfiltered": {
            "note": "Unanchored context only — includes Firefox's own code/strings and default onion list. Not evidence on its own.",
            "total_strings_extracted": total_strings,
            "urls": {"count": unfiltered_url_count, "sample": unfiltered_url_sample},
            "cookie_like": {"count": unfiltered_cookie_count, "sample": unfiltered_cookie_sample},
        },
        "artifacts": artifacts,
        "truncated": truncated,
        "host_anchoring": {
            "applied": require_host_anchor,
            "note": "credentials/search_queries only count as targeted evidence when the same extracted "
            "string also mentions --onion/--host; a full-memory image scans every process's memory, not "
            "just one browser's, and this is the closest proxy for 'this belongs to the target' without "
            "true per-process attribution (see volatility_analyze.py process extraction for that). NOT "
            "applied to cookies (COOKIE_RE's exact app-specific name is already precise, and a cookie "
            "isn't co-located in memory with the page that set it -- this dropped a real session cookie "
            "in testing) or to source_type='process' dumps (already scoped to one process). Hits that "
            "fail this check are kept below, not discarded, just excluded from 'targeted'.",
            "unanchored": {
                category: {
                    "count": unanchored_counts[category],
                    "sample": unanchored_samples[category],
                }
                for category in ("credentials", "search_queries")
            },
        },
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }


def format_summary(report: dict) -> str:
    d, t, tg, u = report["dump"], report["targeting"], report["targeted"], report["unfiltered"]
    kf, sugg, tl = report["key_findings"], report["targeting_suggestions"], report["timeline"]
    lines = [
        "=== TRANCE Memory Analysis ===",
        f"Dump: {d['path']} ({d['size_bytes']:,} bytes, source_type={d.get('source_type', DEFAULT_SOURCE_TYPE)!r})",
        f"SHA-256: {d['sha256']}",
        {
            True: "Integrity: OK (matches .sha256 sidecar)",
            None: "Integrity: no .sha256 sidecar found, unverified",
        }[d["integrity_verified"]],
        f"Targeting: onion={t['onion']!r} host={t['host']!r} username={t['username']!r}",
    ]
    if report.get("truncated"):
        record_cap = report.get("record_cap", MAX_RECORDS_PER_TYPE)
        capped = ", ".join(sorted(report["truncated"]))
        lines.append(f"[!] Result cap ({record_cap:,}/type) hit — truncated: {capped}")
    ha = report.get("host_anchoring")
    if ha and ha["applied"]:
        dropped = sum(v["count"] for v in ha["unanchored"].values())
        if dropped:
            lines.append(
                f"[i] Host-anchoring dropped {dropped} cookie/credential/search-query hit(s) not "
                f"co-located with --onion/--host in the same string (full-memory scan) — see "
                f"'host_anchoring.unanchored' in the JSON report."
            )
    lines += [
        "",
        "=== KEY FINDINGS (deduplicated, high-confidence) ===",
    ]
    if sugg:
        lines.append(
            "[!] Onion address(es) seen repeatedly in memory but NOT covered by --onion/--host "
            "(note: Tor Browser's own bundled default services — search engine, connectivity checks — "
            "also land here and aren't necessarily user activity; check before assuming a missed target):"
        )
        lines += [
            f"    {s['onion']}  (seen {s['hit_count']}x) — re-run with --onion {s['onion']}"
            for s in sugg
        ]
    lines.append(f"--- Session/cookie values ({len(kf['session_cookies'])} unique) ---")
    lines += [
        f"  [{i['offset']}] {i['name']}={i['value']}"
        + (f"  (x{i['occurrences']})" if i["occurrences"] > 1 else "")
        for i in kf["session_cookies"]
    ]
    lines.append(f"--- Credentials ({len(kf['credentials'])} unique) ---")
    lines += [
        f"  [{i['offset']}] {i['field']}={i['value']} [{i['shape']}]"
        + (f"  (x{i['occurrences']})" if i["occurrences"] > 1 else "")
        for i in kf["credentials"]
    ]
    lines.append(f"--- Downloaded files ({len(kf['downloads'])} unique) ---")
    lines += [f"  {v}" for v in kf["downloads"]]
    lines.append(f"--- Target URLs seen ({len(kf['target_urls_seen'])} unique) ---")
    lines += [f"  {v}" for v in kf["target_urls_seen"]]

    lines += [
        "",
        "=== CANDIDATE ACTIVITY SEQUENCE (offset-order, NOT a verified timeline) ===",
        f"  {tl['disclaimer']}",
        "",
    ]
    lines += [f"  {i + 1:>3}. [{e['offset']}] {e['detail']}" for i, e in enumerate(tl["events"])]

    lines += [
        "",
        "=== FULL DETAIL (includes low-confidence noise) ===",
        f"--- Targeted URLs ({len(tg['urls'])}) ---",
    ]
    lines += [f"  [{i['offset']}] {i['value']}" for i in tg["urls"]]
    lines.append(f"--- Cookies ({len(tg['cookies'])}) ---")
    lines += [
        f"  [{i['offset']}] {i['name']}={i['value']}  ({i['confidence']})" for i in tg["cookies"]
    ]
    lines.append(f"--- Search queries ({len(tg['search_queries'])}) ---")
    lines += [
        f"  [{i['offset']}] q={i['value']}"
        + ("  <-- matches --username" if i["matches_username"] else "")
        for i in tg["search_queries"]
    ]
    lines.append(f"--- Credential submissions ({len(tg['credentials'])}) ---")
    lines += [
        f"  [{i['offset']}] {i['field']}={i['value']} [{i['shape']}]  ({i['confidence']})"
        for i in tg["credentials"]
    ]
    lines.append(f"--- Downloads ({len(tg['downloads'])}) ---")
    lines += [f"  [{i['offset']}] {i['value']}  ({i['confidence']})" for i in tg["downloads"]]
    lines += [
        "",
        "--- Unfiltered context (NOISY, not evidence) ---",
        f"  Total printable strings extracted: {u['total_strings_extracted']:,}",
        f"  All URL-like strings seen: {u['urls']['count']} (sample of {len(u['urls']['sample'])} shown)",
    ]
    lines += [f"    {s}" for s in u["urls"]["sample"]]
    lines.append(
        f"  All session/token/auth-like assignments: {u['cookie_like']['count']} "
        f"(sample of {len(u['cookie_like']['sample'])} shown)"
    )
    lines += [f"    {s}" for s in u["cookie_like"]["sample"]]
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Analyze a firefox.exe memory dump for Tor Browser artifacts, anchored to a known target."
    )
    parser.add_argument("dump", type=Path, help="Path to the .bin memory dump")
    parser.add_argument("--onion", help="Target .onion address to anchor URL matching to")
    parser.add_argument(
        "--host", help="Target host[:port] to anchor URL matching to (e.g. 127.0.0.1:5000)"
    )
    parser.add_argument(
        "--username", help="Known username to highlight in recovered search queries"
    )
    parser.add_argument(
        "--min-length",
        type=int,
        default=DEFAULT_MIN_LEN,
        help="Minimum string length to extract (default: %(default)s)",
    )
    parser.add_argument(
        "--source-type",
        choices=sorted(SOURCE_TYPE_RECORD_CAPS),
        default=DEFAULT_SOURCE_TYPE,
        help="What kind of image this is — a single process dump (dumper.py) or a full "
        "physical-memory image (winpmem_acquire.py). Only changes per-category result caps "
        "and report labeling, not extraction logic (default: %(default)s)",
    )
    parser.add_argument(
        "--output", type=Path, help="Path for the JSON report (default: <dump>.report.json)"
    )
    args = parser.parse_args()

    if not args.onion and not args.host:
        print(
            "[!] Warning: no --onion or --host given — targeted URL section will be empty.",
            file=sys.stderr,
        )

    try:
        report = analyze(
            args.dump,
            args.onion,
            args.host,
            args.username,
            min_len=args.min_length,
            source_type=args.source_type,
        )
    except (ParsingError, IntegrityError) as exc:
        print(f"[!] {exc}", file=sys.stderr)
        sys.exit(1)

    output_path = args.output or args.dump.with_name(args.dump.name + ".report.json")
    output_path.write_text(json.dumps(report, indent=2))

    print(format_summary(report))
    print(f"\n[*] JSON report written to {output_path}")
    print(
        "[*] For the HTML case report (all modules, findings.json), run main.py from the repo root."
    )


if __name__ == "__main__":
    main()
