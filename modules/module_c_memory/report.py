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

from modules.module_c_memory.analyzer import is_timeline_noise

# Two consecutive timeline events this close together in the address space more likely
# reflect one rendered page's set of links than two separate sequential navigations.
CLUSTER_GAP_BYTES = 16 * 1024

# A session/cookie/download event sitting more than this many times farther from the
# earliest event than the sequence's typical (median) gap almost certainly reflects
# where that data type happens to live in memory, not when it was created.
FAR_FROM_START_MULTIPLIER = 10

# How similar two recovered paths need to be (0-1, difflib ratio) and how close in
# length, to flag one as a possible typo/probe variant of the other — tuned to catch
# "/favicon.ico" vs "/favicon.icox" without pairing every path that shares a prefix.
NEAR_DUPLICATE_CUTOFF = 0.9
NEAR_DUPLICATE_MAX_LEN_DIFF = 2

# Human-readable labels for the report; keyed on the fully-qualified plugin name
# volatility_analyze.py runs (also its dict key in details["volatility3"]["plugins"]).
VOL3_PLUGIN_LABELS = {
    "windows.psscan.PsScan": "Processes (psscan)",
    "windows.netscan.NetScan": "Network connections (netscan)",
    "windows.filescan.FileScan": "Open files (filescan)",
    "windows.cmdline.CmdLine": "Process command lines (cmdline)",
    "windows.registry.hivelist.HiveList": "Registry hives (hivelist)",
}
VOL3_TABLE_CAP = 100


def _site_map(urls: list[dict]) -> tuple[list[str], list[str]]:
    """(pages, assets): distinct target paths, with automatic asset loads split out."""
    pages = sorted({u["path"] for u in urls if not u["asset"]})
    assets = sorted({u["path"] for u in urls if u["asset"]})
    return pages, assets


def _flag_near_duplicate_paths(pages: list[str], assets: list[str]) -> dict[str, list[str]]:
    """page path -> known paths it closely resembles (possible typo or endpoint probing).
    Compared against assets too, so "/favicon.icox" is caught against "/favicon.ico"."""
    known = pages + assets
    flags: dict[str, list[str]] = {}
    for p in pages:
        others = [o for o in known if o != p and abs(len(o) - len(p)) <= NEAR_DUPLICATE_MAX_LEN_DIFF]
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


def _vol3_rows(plugins: dict, name_suffix: str) -> list[dict]:
    """Rows from the one plugin result whose name ends in `name_suffix` (a plain
    class-name shorthand -- e.g. "PsScan" for "windows.psscan.PsScan") if it ran
    cleanly, else []. Matching on the class name keeps this independent of exactly
    which fully-qualified plugin name volatility_analyze.py used."""
    for name, result in plugins.items():
        if name.endswith(name_suffix) and result.get("status") == "ok":
            return result["rows"]
    return []


def _vol3_process_corroboration(psscan_rows: list[dict]) -> list[str]:
    """Note, don't score: when psscan independently confirms a browser process existed,
    that's worth surfacing next to the string-carver evidence that assumed one did --
    not merged into it. See module docstring / task spec: juxtaposition only, no
    automated confidence blending."""
    notes = []
    for row in psscan_rows:
        name = (row.get("ImageFileName") or "").lower()
        if "firefox" not in name:
            continue
        exited = f", exited {row['ExitTime']}" if row.get("ExitTime") else " — still running at capture time"
        notes.append(
            f"windows.psscan independently confirms a firefox.exe process existed "
            f"(PID {row.get('PID')}, created {row.get('CreateTime')}{exited}). Structural "
            f"corroboration of the process the string-carver evidence below was extracted from."
        )
    return notes


def _vol3_network_corroboration(netscan_rows: list[dict], host_target: str | None) -> list[str]:
    if not host_target:
        return []
    target_host, _, target_port = host_target.partition(":")
    notes = []
    for row in netscan_rows:
        for addr_key, port_key in (("LocalAddr", "LocalPort"), ("ForeignAddr", "ForeignPort")):
            if row.get(addr_key) != target_host:
                continue
            if target_port and str(row.get(port_key)) != target_port:
                continue
            notes.append(
                f"windows.netscan independently observed a connection matching --host "
                f"{host_target} (PID {row.get('PID')}, {row.get('Proto')}, state {row.get('State')}). "
                f"Structural corroboration of the target the URL/cookie evidence was anchored to."
            )
            break
    return notes


def _vol3_file_corroboration(filescan_rows: list[dict], confirmed_downloads: list[str]) -> list[str]:
    download_names = {d.replace("\\", "/").rstrip("/").rsplit("/", 1)[-1] for d in confirmed_downloads}
    download_names.discard("")
    notes = []
    for row in filescan_rows:
        path = (row.get("Name") or "").replace("\\", "/").rstrip("/")
        base = path.rsplit("/", 1)[-1] if path else ""
        if base and base in download_names:
            notes.append(
                f"windows.filescan independently lists a file named {base!r}. Matches a download "
                f"the string carver confirmed under a real \\Downloads\\ folder."
            )
    return notes


def _vol3_context(details: dict) -> dict:
    """Presentation context for the Volatility3 structural-analysis section. Kept fully
    separate from the string-carver sections above it -- every plugin result already
    carries its own "source": "volatility3:<plugin>" tag (see volatility_analyze.py), and
    nothing here merges a vol3 row into a string-carver finding or vice versa. The
    `corroboration` notes are plain text pointing at two independent pieces of evidence
    that happen to agree -- not a score, not a merge."""
    vol3 = details.get("volatility3") or {"status": "skipped", "message": None, "plugins": {}}
    plugins = vol3.get("plugins", {})

    plugin_views = []
    for name, result in plugins.items():
        rows = result.get("rows", [])
        plugin_views.append(
            {
                "name": name,
                "label": VOL3_PLUGIN_LABELS.get(name, name),
                "status": result.get("status"),
                "message": result.get("message"),
                "total_rows": result.get("row_count", len(rows)),
                "rows": rows[:VOL3_TABLE_CAP],
                "truncated": len(rows) > VOL3_TABLE_CAP,
            }
        )
    plugin_views.sort(key=lambda p: list(VOL3_PLUGIN_LABELS).index(p["name"]) if p["name"] in VOL3_PLUGIN_LABELS else 99)

    corroboration = (
        _vol3_process_corroboration(_vol3_rows(plugins, "PsScan"))
        + _vol3_network_corroboration(_vol3_rows(plugins, "NetScan"), details["targeting"].get("host"))
        + _vol3_file_corroboration(_vol3_rows(plugins, "FileScan"), details["key_findings"]["downloads"])
    )

    return {
        "status": vol3.get("status", "skipped"),
        "message": vol3.get("message"),
        "vol_bin": vol3.get("vol_bin"),
        "plugins": plugin_views,
        "corroboration": corroboration,
    }


def build_context(details: dict) -> dict:
    """Presentation context for the memory section of the case report."""
    site_map, assets = _site_map(details["targeted"]["urls"])
    events = _annotate_timeline(details["timeline"]["events"])
    return {
        "details": details,
        "site_map": site_map,
        "assets": assets,
        "near_duplicates": _flag_near_duplicate_paths(site_map, assets),
        "events": events,
        "session_cookies": _annotate_session_cookies(details["key_findings"]["session_cookies"]),
        "downloads": _annotate_downloads(details["key_findings"]["downloads"], site_map),
        "search_terms": _search_term_frequencies(
            details["targeted"]["search_queries"], details["targeting"]["username"]
        ),
        "any_clustered": any(e["clustered_with_prev"] for e in events),
        "any_far_from_start": any(e["far_from_start"] for e in events),
        "cluster_gap_bytes": CLUSTER_GAP_BYTES,
        "volatility3": _vol3_context(details),
    }
