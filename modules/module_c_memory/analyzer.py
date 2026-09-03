"""Offline, target-anchored analysis of a firefox.exe memory dump (.bin) produced by dumper.py."""

from __future__ import annotations

import argparse
import json
import re
import sys
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

URL_RE = re.compile(r"https?://[^\s\"'<>\\]+")
ONION_RE = re.compile(r"[a-z2-7]{16,56}\.onion(?::\d+)?[^\s\"'<>\\]*", re.IGNORECASE)
COOKIE_RE = re.compile(r"\b(session|trance_user|trance_pref)=([^\s;\"'<>]+)")
SEARCH_QUERY_RE = re.compile(r"\?q=([^\s&\"'<>]+)")
CREDENTIAL_RE = re.compile(r"\b(username|password)=([^\s&\"'<>]+)")
NOISY_COOKIE_RE = re.compile(r"\b(\w*(?:session|token|auth|cookie|csrf)\w*)=([^\s;\"'<>]{1,80})", re.IGNORECASE)


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
    artifacts: list[dict] = []

    total_strings = 0
    unfiltered_url_count = 0
    unfiltered_url_sample: list[str] = []
    unfiltered_cookie_count = 0
    unfiltered_cookie_sample: list[str] = []

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

        for m in COOKIE_RE.finditer(s):
            name, value = m.group(1), m.group(2)
            match_offset = offset + m.start()
            cookies.append({"offset": hex(match_offset), "name": name, "value": value})
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
            credentials.append({"offset": hex(match_offset), "field": field, "value": value})
            record_artifact("credential", match_offset, f"{field}={value}")

    return {
        "dump": {
            "path": str(dump_path),
            "size_bytes": dump_path.stat().st_size,
            "sha256": hash_file(dump_path),
            "integrity_verified": integrity_verified,
        },
        "targeting": {"onion": onion, "host": host, "username": username},
        "targeted": {
            "urls": urls,
            "cookies": cookies,
            "search_queries": search_queries,
            "credentials": credentials,
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
        f"--- Targeted URLs ({len(tg['urls'])}) ---",
    ]
    lines += [f"  [{i['offset']}] {i['value']}" for i in tg["urls"]]
    lines.append(f"--- Cookies ({len(tg['cookies'])}) ---")
    lines += [f"  [{i['offset']}] {i['name']}={i['value']}" for i in tg["cookies"]]
    lines.append(f"--- Search queries ({len(tg['search_queries'])}) ---")
    lines += [
        f"  [{i['offset']}] q={i['value']}" + ("  <-- matches --username" if i["matches_username"] else "")
        for i in tg["search_queries"]
    ]
    lines.append(f"--- Credential submissions ({len(tg['credentials'])}) ---")
    lines += [f"  [{i['offset']}] {i['field']}={i['value']}" for i in tg["credentials"]]
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
