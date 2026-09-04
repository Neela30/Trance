"""Module C's contribution to the case report: turn analyzer output into presentation context.

This does not render anything — the root-level `report.py` owns the template and the
HTML. This only prepares the memory-specific view of `details` (the dict analyze()
returns, as stored under modules.module_c_memory.details in findings.json).

Deterministic and offline — no LLM or external API involved anywhere. Every
"interpretation" here (page-cluster grouping, the cookie-storage-region caveat,
near-duplicate path flagging) is a fixed rule applied to evidence analyzer.py already
extracted, not an inference call. That's deliberate: a memory dump is evidentiary, and a
fixed, auditable rule beats a model's judgment call for something that has to be
defensible later. Tune the thresholds below per-case if they don't fit a given dump.
"""

from __future__ import annotations

import base64
import difflib
import json
from collections import Counter
from urllib.parse import urlsplit

from modules.module_c_memory.analyzer import ORIGIN_ATTR_RE, is_timeline_noise

# Two consecutive timeline events this close together in the address space more likely
# reflect one rendered page's set of links than two separate sequential navigations.
CLUSTER_GAP_BYTES = 16 * 1024

# A session/cookie/download event sitting more than this many times farther from the
# earliest event than the sequence's typical (median) gap almost certainly reflects
# where that data type happens to live in memory, not when it was created.
FAR_FROM_START_MULTIPLIER = 10

# How similar two recovered paths need to be (0-1, difflib ratio) to flag one as a
# possible typo/probe variant of the other, e.g. "/favicon.ico" vs "/favicon.icox".
NEAR_DUPLICATE_CUTOFF = 0.85


def _clean_site_map(urls: list[dict]) -> list[str]:
    """Canonical path+query for each recovered target URL, skipping internal noise."""
    paths: set[str] = set()
    for u in urls:
        value = u["value"]
        if ORIGIN_ATTR_RE.search(value) or "://" not in value:
            continue
        parts = urlsplit(value)
        path = parts.path or "/"
        if parts.query:
            path = f"{path}?{parts.query}"
        paths.add(path)
    return sorted(paths)


def _flag_near_duplicate_paths(paths: list[str]) -> dict[str, list[str]]:
    """path -> other paths it closely resembles (possible typo or endpoint probing)."""
    flags: dict[str, list[str]] = {}
    for p in paths:
        others = [o for o in paths if o != p]
        close = difflib.get_close_matches(p, others, n=3, cutoff=NEAR_DUPLICATE_CUTOFF)
        if close:
            flags[p] = close
    return flags


def _try_decode_jwt_like_payload(value: str) -> str | None:
    """If `value` has a dot-separated base64url segment whose first part is JSON
    (Flask/itsdangerous session cookies, JWTs), return that JSON. Not tied to any one
    app's token shape — just the generic base64url.JSON convention."""
    segment = value.split(".", 1)[0]
    padded = segment + "=" * (-len(segment) % 4)
    try:
        decoded = base64.urlsafe_b64decode(padded)
        parsed = json.loads(decoded)
    except Exception:
        return None
    return json.dumps(parsed)


def _annotate_session_cookies(cookies: list[dict]) -> list[dict]:
    return [{**c, "decoded_payload": _try_decode_jwt_like_payload(c["value"])} for c in cookies]


def _match_download_to_site_map(download_value: str, site_map: list[str]) -> str | None:
    """If a confirmed local download's filename matches a recovered path's last segment
    (local 'evidence_report.txt' <-> '/download/evidence_report.txt'), surface that
    correlation — it's the strongest evidence a link was actually used."""
    name = download_value.replace("\\", "/").rstrip("/").rsplit("/", 1)[-1]
    for path in site_map:
        if path.split("?", 1)[0].rsplit("/", 1)[-1] == name:
            return path
    return None


def _annotate_downloads(downloads: list[str], site_map: list[str]) -> list[dict]:
    return [{"value": v, "matched_endpoint": _match_download_to_site_map(v, site_map)} for v in downloads]


def _search_term_frequencies(search_queries: list[dict], username: str | None) -> list[dict]:
    """Deduped search/typed-term counts, skipping browser template noise — same rule
    analyzer.py's own timeline uses, so counts here always agree with the timeline."""
    counts = Counter(q["value"] for q in search_queries if not is_timeline_noise(q["value"]))
    return [
        {"value": v, "count": c, "matches_username": bool(username) and username.lower() in v.lower()}
        for v, c in counts.most_common()
    ]


def _annotate_timeline(events: list[dict]) -> list[dict]:
    """Attach cluster/far-from-start flags to timeline events via fixed offset math."""
    if not events:
        return []
    offsets = [int(e["offset"], 16) for e in events]
    earliest = offsets[0]
    gaps = [offsets[i] - offsets[i - 1] for i in range(1, len(offsets))]
    median_gap = sorted(gaps)[len(gaps) // 2] if gaps else 0

    annotated = []
    for i, e in enumerate(events):
        off = offsets[i]
        clustered_with_prev = i > 0 and (off - offsets[i - 1]) <= CLUSTER_GAP_BYTES
        far_from_start = (
            e["type"] in ("session", "download", "credential")
            and median_gap > 0
            and (off - earliest) > median_gap * FAR_FROM_START_MULTIPLIER
        )
        annotated.append({**e, "clustered_with_prev": clustered_with_prev, "far_from_start": far_from_start})
    return annotated


def build_context(details: dict) -> dict:
    """Presentation context for the memory section of the case report."""
    site_map = _clean_site_map(details["targeted"]["urls"])
    events = _annotate_timeline(details["timeline"]["events"])
    return {
        "details": details,
        "site_map": site_map,
        "near_duplicates": _flag_near_duplicate_paths(site_map),
        "events": events,
        "session_cookies": _annotate_session_cookies(details["key_findings"]["session_cookies"]),
        "downloads": _annotate_downloads(details["key_findings"]["downloads"], site_map),
        "search_terms": _search_term_frequencies(
            details["targeted"]["search_queries"], details["targeting"]["username"]
        ),
        "any_clustered": any(e["clustered_with_prev"] for e in events),
        "any_far_from_start": any(e["far_from_start"] for e in events),
        "cluster_gap_bytes": CLUSTER_GAP_BYTES,
    }
