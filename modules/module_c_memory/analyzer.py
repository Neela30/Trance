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

URL_RE = re.compile(r"https?://[^\s\"'<>\\]+")
ONION_RE = re.compile(r"[a-z2-7]{16,56}\.onion(?::\d+)?[^\s\"'<>\\]*", re.IGNORECASE)
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


# A hit under \Downloads\ (Windows' actual save-to location, incl. the
# browser's own portable installer if the user downloaded it) is real user
# evidence. A hit anywhere else in a file:// URI or path (Tor Browser's own
# install dir, its extensions/omni.ja, %AppData%\...\OneDrive, etc.) is the
# browser/OS's own files, not something the user fetched.
_DOWNLOADS_DIR_RE = re.compile(r"downloads[\\/]", re.IGNORECASE)


def _is_confirmed_download(value: str) -> bool:
    return bool(_DOWNLOADS_DIR_RE.search(value))


# Search-query / urlbar noise: Firefox's own template placeholders and
# origin-attribute-suffixed URLs (Firefox's internal principal serialization,
# e.g. "<url>^privateBrowsingId=1&firstPartyDomain=..." — never something a
# person typed or navigated to).
_TEMPLATE_NOISE_RE = re.compile(r"[{}]|searchTerms|TERMS%|^%s$")
_ORIGIN_ATTR_RE = re.compile(r"\^privateBrowsingId|\^partitionKey|\^firstPartyDomain")


def _is_timeline_noise(value: str) -> bool:
    return bool(_is_noise_value(value) or _TEMPLATE_NOISE_RE.search(value) or _ORIGIN_ATTR_RE.search(value))


def _ascii_pattern(min_len: int) -> re.Pattern[bytes]:
    return re.compile(rb"[\x20-\x7e]{%d,}" % min_len)


def _utf16le_pattern(min_len: int) -> re.Pattern[bytes]:
    return re.compile(rb"(?:[\x20-\x7e]\x00){%d,}" % min_len)


def iter_strings(path: Path, min_len: int = DEFAULT_MIN_LEN) -> Iterator[tuple[int, str]]:
    """Yield (offset, string) for printable ASCII and UTF-16LE runs, chunked to bound memory use."""
    ascii_re = _ascii_pattern(min_len)
    utf16_re = _utf16le_pattern(min_len)
    seen_offsets: set[int] = set()
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
                if abs_off not in seen_offsets:
                    seen_offsets.add(abs_off)
                    yield abs_off, m.group().decode("ascii")
            for m in utf16_re.finditer(window):
                abs_off = window_start + m.start()
                if abs_off not in seen_offsets:
                    seen_offsets.add(abs_off)
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

    for u in urls:
        if _ORIGIN_ATTR_RE.search(u["value"]):
            continue
        add_event("page_visit", f"Visited {u['value']}", u["value"], u["offset"])

    for c in cookies:
        if c["confidence"] != "high":
            continue
        add_event("session", f"Session value observed: {c['name']}={c['value']}", f"{c['name']}={c['value']}", c["offset"])

    for q in search_queries:
        if _is_timeline_noise(q["value"]):
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
) -> dict:
    if not dump_path.exists():
        raise ParsingError(f"Dump file not found: {dump_path}")

    integrity_verified = verify_integrity(dump_path)
    targets = [t.lower() for t in (onion, host) if t]

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

    def record_artifact(artifact_type: str, offset: int, description: str) -> None:
        artifacts.append(
            asdict(
                Artifact(
                    module="module_c_memory",
                    artifact_type=artifact_type,
                    source=f"offset {hex(offset)}",
                    description=description,
                )
            )
        )

    for offset, s in iter_strings(dump_path, min_len=min_len):
        total_strings += 1

        for m in list(URL_RE.finditer(s)) + list(ONION_RE.finditer(s)):
            url = m.group()
            match_offset = offset + m.start()
            unfiltered_url_count += 1
            if len(unfiltered_url_sample) < SAMPLE_CAP:
                unfiltered_url_sample.append(url)
            if targets and any(t in url.lower() for t in targets):
                urls.append({"offset": hex(match_offset), "value": url})
                record_artifact("url", match_offset, url)
        for m in ONION_DOMAIN_RE.finditer(s):
            onion_domain_hits[m.group().lower()] += 1

        for m in COOKIE_RE.finditer(s):
            name, value = m.group(1), m.group(2)
            match_offset = offset + m.start()
            confidence = "low" if _is_noise_value(value) else "high"
            cookies.append(
                {"offset": hex(match_offset), "name": name, "value": value, "confidence": confidence}
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
            search_queries.append({"offset": hex(match_offset), "value": value, "matches_username": matches_username})
            record_artifact("search_query", match_offset, value)

        for m in CREDENTIAL_RE.finditer(s):
            field, value = m.group(1), m.group(2)
            match_offset = offset + m.start()
            confidence = "low" if _is_noise_value(value) else "high"
            credentials.append(
                {"offset": hex(match_offset), "field": field, "value": value, "shape": "form", "confidence": confidence}
            )
            record_artifact("credential", match_offset, f"{field}={value}")
        for m in CREDENTIAL_JSON_RE.finditer(s):
            field, value = m.group(1), m.group(2)
            match_offset = offset + m.start()
            confidence = "low" if _is_noise_value(value) else "high"
            credentials.append(
                {"offset": hex(match_offset), "field": field, "value": value, "shape": "json", "confidence": confidence}
            )
            record_artifact("credential", match_offset, f'"{field}":"{value}"')

        for m in list(FILE_URI_RE.finditer(s)) + list(DOWNLOAD_PATH_RE.finditer(s)):
            value = m.group()
            match_offset = offset + m.start()
            confidence = "high" if _is_confirmed_download(value) else "low"
            downloads.append({"offset": hex(match_offset), "value": value, "confidence": confidence})
            record_artifact("download", match_offset, value)

    # Tor Browser itself talks to a handful of bundled default onion services
    # (search engine, connectivity checks) whether or not the user does
    # anything — those show up here too and are expected background noise,
    # not evidence of user action. Capped and left unlabeled rather than
    # guessing which specific v3 addresses are "default" (those can rotate).
    targeting_suggestions = [
        {"onion": domain, "hit_count": count}
        for domain, count in onion_domain_hits.most_common(10)
        if count >= SUGGESTION_MIN_HITS and not any(domain in t for t in targets)
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
        },
        "targeting": {"onion": onion, "host": host, "username": username},
        "targeting_suggestions": targeting_suggestions,
        "key_findings": {
            "note": "Deduplicated, high-confidence hits only — start here. Full detail incl. low-confidence "
            "noise is in 'targeted' below.",
            "session_cookies": key_cookies,
            "credentials": key_credentials,
            "downloads": key_downloads,
            "target_urls_seen": sorted({u["value"] for u in urls}),
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
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }


def format_summary(report: dict) -> str:
    d, t, tg, u = report["dump"], report["targeting"], report["targeted"], report["unfiltered"]
    kf, sugg, tl = report["key_findings"], report["targeting_suggestions"], report["timeline"]
    lines = [
        "=== TRANCE Memory Analysis ===",
        f"Dump: {d['path']} ({d['size_bytes']:,} bytes)",
        f"SHA-256: {d['sha256']}",
        {
            True: "Integrity: OK (matches .sha256 sidecar)",
            None: "Integrity: no .sha256 sidecar found, unverified",
        }[d["integrity_verified"]],
        f"Targeting: onion={t['onion']!r} host={t['host']!r} username={t['username']!r}",
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
    parser.add_argument("--output", type=Path, help="Path for the JSON report (default: <dump>.report.json)")
    args = parser.parse_args()

    if not args.onion and not args.host:
        print("[!] Warning: no --onion or --host given — targeted URL section will be empty.", file=sys.stderr)

    try:
        report = analyze(args.dump, args.onion, args.host, args.username, min_len=args.min_length)
    except (ParsingError, IntegrityError) as exc:
        print(f"[!] {exc}", file=sys.stderr)
        sys.exit(1)

    output_path = args.output or args.dump.with_name(args.dump.name + ".report.json")
    output_path.write_text(json.dumps(report, indent=2))

    print(format_summary(report))
    print(f"\n[*] JSON report written to {output_path}")


if __name__ == "__main__":
    main()
