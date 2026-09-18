"""Offline, target-anchored analysis of a firefox.exe memory dump (.bin) produced by dumper.py."""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections import Counter
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator

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
NOISY_COOKIE_RE = re.compile(r"\b(\w*(?:session|token|auth|cookie|csrf)\w*)=([^\s;\"'<>]{1,80})", re.IGNORECASE)
# Local download evidence: Firefox's in-memory download manager / session
# strings carry either a file:// URI or an absolute Windows path ending in a
# common downloaded-file extension.
FILE_URI_RE = re.compile(r"file:///[^\s\"'<>\\]+", re.IGNORECASE)
DOWNLOAD_PATH_RE = re.compile(
    r"[A-Za-z]:\\(?:Users|Downloads)[^\x00-\x1f\"'<>|]*?"
    r"\.(?:pdf|zip|rar|7z|exe|msi|docx?|xlsx?|pptx?|csv|txt|jpg|jpeg|png|gif|mp4|mp3|iso|dat)\b",
    re.IGNORECASE,
)
# Values that are Firefox's own printf-style format strings ("%p", "%lld.")
# or single/near-empty leftovers ("a", "]") rather than real captured data —
# these otherwise drown out genuine hits under the same exact-name regex.
_NOISE_VALUE_RE = re.compile(r"^%|^.{1,2}$")


def _is_noise_value(value: str) -> bool:
    return bool(_NOISE_VALUE_RE.match(value))


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
    ".css", ".js", ".map", ".ico", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp",
    ".woff", ".woff2", ".ttf",
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


def iter_strings(path: Path, min_len: int = DEFAULT_MIN_LEN) -> Iterator[tuple[int, str]]:
    """Yield (offset, string) for printable ASCII and UTF-16LE runs, chunked to bound memory use."""
    ascii_re = _ascii_pattern(min_len)
    utf16_re = _utf16le_pattern(min_len)
    # finditer() yields strictly increasing start offsets within a window, and the only
    # duplicates across windows are re-scans of the carried-over overlap region — so a
    # per-pattern high-water mark dedupes exactly like a seen-offsets set would, without
    # holding one Python int per match for the life of the scan (matters once "the dump"
    # is a multi-GB physical-RAM image or pagefile instead of a single process's memory).
    ascii_floor = -1
    utf16_floor = -1
    with open(path, "rb") as f:
        offset = 0
        carry = b""
        while True:
            chunk = f.read(CHUNK_SIZE)
            if not chunk:
                break
            window = carry + chunk
            window_start = offset - len(carry)
            for m in ascii_re.finditer(window):
                abs_off = window_start + m.start()
                if abs_off > ascii_floor:
                    ascii_floor = abs_off
                    yield abs_off, m.group().decode("ascii")
            for m in utf16_re.finditer(window):
                abs_off = window_start + m.start()
                if abs_off > utf16_floor:
                    utf16_floor = abs_off
                    yield abs_off, m.group().decode("utf-16-le", errors="ignore")
            offset += len(chunk)
            carry = window[-OVERLAP:] if len(window) > OVERLAP else window


def verify_integrity(dump_path: Path) -> bool | None:
    """Return True if a <dump>.sha256 sidecar matches, None if no sidecar exists, else raise."""
    sidecar = dump_path.with_name(dump_path.name + ".sha256")
    if not sidecar.exists():
        return None
    expected = sidecar.read_text().split()[0].strip().lower()
    actual = hash_file(dump_path)
    if expected != actual:
        raise IntegrityError(f"Hash mismatch for {dump_path}: sidecar says {expected}, computed {actual}")
    return True


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
        add_event("session", f"Session value observed: {c['name']}={c['value']}", f"{c['name']}={c['value']}", c["offset"])

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
        add_event("credential", f"Credential submitted: {cr['field']}={cr['value']}", f"{cr['field']}={cr['value']}", cr["offset"])

    for d in downloads:
        if d["confidence"] != "high":
            continue
        add_event("download", f"Downloaded: {d['value']}", d["value"], d["offset"])

    return sorted(events.values(), key=lambda e: int(e["offset"], 16))


def analyze(
    dump_path: Path,
    onion: str | None,
    host: str | None,
    username: str | None,
    min_len: int = DEFAULT_MIN_LEN,
    source_type: str = DEFAULT_SOURCE_TYPE,
) -> dict:
    if not dump_path.exists():
        raise ParsingError(f"Dump file not found: {dump_path}")

    integrity_verified = verify_integrity(dump_path)
    targets = [t.lower() for t in (onion, host) if t]
    record_cap = SOURCE_TYPE_RECORD_CAPS.get(source_type, MAX_RECORDS_PER_TYPE)

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

    for offset, s in iter_strings(dump_path, min_len=min_len):
        total_strings += 1

        url_spans: list[tuple[int, int]] = []
        url_hits: list[tuple[int, str, str, str]] = []
        for m in URL_RE.finditer(s):
            url_spans.append((m.start(), m.end()))
            host, path = _split_url(m.group())
            url_hits.append((m.start(), m.group(), host, path))
        for m in ONION_RE.finditer(s):
            # Inside a full URL it's already covered by that URL (or is a search engine
            # merely mentioning it); without a path it's a mention, not a visit.
            if not m.group("path") or any(a <= m.start() < b for a, b in url_spans):
                continue
            url_hits.append((m.start(), m.group(), m.group("host").lower(), m.group("path")))
        for start, url, host, path in url_hits:
            match_offset = offset + start
            unfiltered_url_count += 1
            if len(unfiltered_url_sample) < SAMPLE_CAP:
                unfiltered_url_sample.append(url)
            if targets and _matches_target(host, targets):
                append_capped(
                    urls,
                    {
                        "offset": hex(match_offset),
                        "value": url,
                        "host": host,
                        "path": path,
                        "asset": _is_asset_path(path),
                    },
                    "urls",
                )
                record_artifact("url", match_offset, url)
        for m in ONION_DOMAIN_RE.finditer(s):
            onion_domain_hits[m.group().lower()] += 1
            # Only the top 10 ever get reported (targeting_suggestions below); on a
            # whole-system image with many distinct onion-like mentions this dict is
            # the growth risk, so periodically drop everything but the leaders.
            if len(onion_domain_hits) > 10_000:
                onion_domain_hits = Counter(dict(onion_domain_hits.most_common(1_000)))

        for m in COOKIE_RE.finditer(s):
            name, value = m.group(1), m.group(2)
            match_offset = offset + m.start()
            confidence = "low" if _is_noise_value(value) else "high"
            append_capped(
                cookies,
                {"offset": hex(match_offset), "name": name, "value": value, "confidence": confidence},
                "cookies",
            )
            record_artifact("cookie", match_offset, f"{name}={value}")
        for m in NOISY_COOKIE_RE.finditer(s):
            unfiltered_cookie_count += 1
            if len(unfiltered_cookie_sample) < SAMPLE_CAP:
                unfiltered_cookie_sample.append(f"{m.group(1)}={m.group(2)}")

        for m in SEARCH_QUERY_RE.finditer(s):
            value = m.group(1)
            match_offset = offset + m.start()
            matches_username = bool(username) and username.lower() in value.lower()
            append_capped(
                search_queries,
                {"offset": hex(match_offset), "value": value, "matches_username": matches_username},
                "search_queries",
            )
            record_artifact("search_query", match_offset, value)

        for m in CREDENTIAL_RE.finditer(s):
            field, value = m.group(1), m.group(2)
            match_offset = offset + m.start()
            confidence = "low" if _is_noise_value(value) else "high"
            append_capped(
                credentials,
                {"offset": hex(match_offset), "field": field, "value": value, "shape": "form", "confidence": confidence},
                "credentials",
            )
            record_artifact("credential", match_offset, f"{field}={value}")
        for m in CREDENTIAL_JSON_RE.finditer(s):
            field, value = m.group(1), m.group(2)
            match_offset = offset + m.start()
            confidence = "low" if _is_noise_value(value) else "high"
            append_capped(
                credentials,
                {"offset": hex(match_offset), "field": field, "value": value, "shape": "json", "confidence": confidence},
                "credentials",
            )
            record_artifact("credential", match_offset, f'"{field}":"{value}"')

        for m in list(FILE_URI_RE.finditer(s)) + list(DOWNLOAD_PATH_RE.finditer(s)):
            value = m.group()
            match_offset = offset + m.start()
            confidence = "high" if _is_confirmed_download(value) else "low"
            append_capped(
                downloads,
                {"offset": hex(match_offset), "value": value, "confidence": confidence},
                "downloads",
            )
            record_artifact("download", match_offset, value)

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
            "sha256": hash_file(dump_path),
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
        lines += [f"    {s['onion']}  (seen {s['hit_count']}x) — re-run with --onion {s['onion']}" for s in sugg]
    lines.append(f"--- Session/cookie values ({len(kf['session_cookies'])} unique) ---")
    lines += [
        f"  [{i['offset']}] {i['name']}={i['value']}" + (f"  (x{i['occurrences']})" if i["occurrences"] > 1 else "")
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

    lines += ["", "=== FULL DETAIL (includes low-confidence noise) ===", f"--- Targeted URLs ({len(tg['urls'])}) ---"]
    lines += [f"  [{i['offset']}] {i['value']}" for i in tg["urls"]]
    lines.append(f"--- Cookies ({len(tg['cookies'])}) ---")
    lines += [f"  [{i['offset']}] {i['name']}={i['value']}  ({i['confidence']})" for i in tg["cookies"]]
    lines.append(f"--- Search queries ({len(tg['search_queries'])}) ---")
    lines += [
        f"  [{i['offset']}] q={i['value']}" + ("  <-- matches --username" if i["matches_username"] else "")
        for i in tg["search_queries"]
    ]
    lines.append(f"--- Credential submissions ({len(tg['credentials'])}) ---")
    lines += [
        f"  [{i['offset']}] {i['field']}={i['value']} [{i['shape']}]  ({i['confidence']})" for i in tg["credentials"]
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
    parser.add_argument("--host", help="Target host[:port] to anchor URL matching to (e.g. 127.0.0.1:5000)")
    parser.add_argument("--username", help="Known username to highlight in recovered search queries")
    parser.add_argument(
        "--min-length", type=int, default=DEFAULT_MIN_LEN, help="Minimum string length to extract (default: %(default)s)"
    )
    parser.add_argument(
        "--source-type",
        choices=sorted(SOURCE_TYPE_RECORD_CAPS),
        default=DEFAULT_SOURCE_TYPE,
        help="What kind of image this is — a single process dump (dumper.py) or a full "
        "physical-memory image (winpmem_acquire.py). Only changes per-category result caps "
        "and report labeling, not extraction logic (default: %(default)s)",
    )
    parser.add_argument("--output", type=Path, help="Path for the JSON report (default: <dump>.report.json)")
    args = parser.parse_args()

    if not args.onion and not args.host:
        print("[!] Warning: no --onion or --host given — targeted URL section will be empty.", file=sys.stderr)

    try:
        report = analyze(
            args.dump, args.onion, args.host, args.username, min_len=args.min_length, source_type=args.source_type
        )
    except (ParsingError, IntegrityError) as exc:
        print(f"[!] {exc}", file=sys.stderr)
        sys.exit(1)

    output_path = args.output or args.dump.with_name(args.dump.name + ".report.json")
    output_path.write_text(json.dumps(report, indent=2))

    print(format_summary(report))
    print(f"\n[*] JSON report written to {output_path}")
    print("[*] For the HTML case report (all modules, findings.json), run main.py from the repo root.")


if __name__ == "__main__":
    main()
