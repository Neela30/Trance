"""Recover and classify browsing evidence from an extracted Tor Browser profile.

Analyzes places.sqlite, cookies.sqlite, favicons.sqlite and any bookmark
backups pulled from a disk image, separating genuine user activity from
Tor Browser's baked-in first-run defaults (default bookmarks/onion links
that ship with every fresh profile and would otherwise look like history).

Usage:
    python recover_evidence.py <evidence_dir> [--out report.json]

<evidence_dir> is expected to contain: places.sqlite, cookies.sqlite,
favicons.sqlite, hashes.sha256 (optional), bookmarkbackups/ (optional).
"""

from __future__ import annotations

import argparse
import json
import sqlite3
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from core.custody_log import CustodyEntry, CustodyLog
from core.hashing import hash_file

# URLs/titles baked into every fresh Tor Browser profile's "Tor Project
# Bookmarks" folder. Anything matching these is default noise, not evidence
# of user activity, and must be filtered out before drawing conclusions.
DEFAULT_BOOKMARK_URLS = {
    "http://2gzyxa5ihm7nsggfxnu52rck2vv4rvmdlkiu3zzui5du4xyclen53wid.onion/",
    "http://pzhdfe7jraknpj2qgu5cz2u3i4deuyfwmonvzu5i3nyw4t4bmg7o5pad.onion/",
    "http://rzuwtpc4wb3xdzrj3yeajsvm3fkq4vbeubm2tdxaqruzzzgs5dwemlad.onion/",
    "about:manual",
    "http://xmrhfasfg5suueegrnc4gsgyi2tyclcy5oz7f5drnrodmdtob6t2ioyd.onion/",
    "http://v236xhqtyullodhf26szyjepvkbv6iitrhjgrqj4avaoukebkk6n6syd.onion/",
    "https://donate.torproject.org/",
    "http://yq5jjvr7drkjrelzhut7kgclfuro65jjlivyzfmxiq2kyv5lickrl4qd.onion/",
}


def _open_ro(path: Path) -> sqlite3.Connection:
    return sqlite3.connect(f"file:{path}?mode=ro", uri=True)


def verify_hashes(evidence_dir: Path) -> dict:
    hashes_file = evidence_dir / "hashes.sha256"
    result = {}
    if not hashes_file.exists():
        return result
    for line in hashes_file.read_text().splitlines():
        line = line.strip()
        if not line:
            continue
        digest, _, recorded_path = line.partition("  ")
        if not recorded_path:
            digest, _, recorded_path = line.partition(" ")
        fname = Path(recorded_path.strip()).name
        if fname == "hashes.sha256":
            continue  # the manifest doesn't hash itself
        target = evidence_dir / fname
        if not target.exists():
            result[fname] = {"status": "missing"}
            continue
        actual = hash_file(target)
        if actual == digest:
            status = "match"
        elif fname.endswith(("-shm", "-wal")):
            # SQLite rewrites the shared-memory index / WAL on open even in
            # read-only mode; a mismatch here is expected, not tampering.
            status = "changed (expected: -shm/-wal touched by read-only open)"
        else:
            status = "MISMATCH"
        result[fname] = {"status": status, "recorded": digest, "actual": actual}
    return result


def analyze_places(db_path: Path) -> dict:
    if not db_path.exists():
        return {"error": "not found"}
    conn = _open_ro(db_path)
    cur = conn.cursor()

    cur.execute(
        "SELECT id, url, title, visit_count, hidden, typed, last_visit_date "
        "FROM moz_places"
    )
    places = []
    user_activity = []
    for row in cur.fetchall():
        pid, url, title, visit_count, hidden, typed, last_visit_date = row
        is_default = url in DEFAULT_BOOKMARK_URLS
        looks_like_activity = bool(visit_count) or bool(typed) or last_visit_date is not None
        entry = {
            "id": pid,
            "url": url,
            "title": title,
            "visit_count": visit_count,
            "typed": typed,
            "last_visit_date": last_visit_date,
            "default_profile_entry": is_default,
        }
        places.append(entry)
        if looks_like_activity and not is_default:
            user_activity.append(entry)

    cur.execute("SELECT COUNT(*) FROM moz_historyvisits")
    historyvisits_count = cur.fetchone()[0]

    cur.execute("SELECT COUNT(*) FROM moz_inputhistory")
    inputhistory_count = cur.fetchone()[0]

    cur.execute("SELECT COUNT(*) FROM moz_annos")
    annos_count = cur.fetchone()[0]

    cur.execute("SELECT COUNT(*) FROM moz_keywords")
    keywords_count = cur.fetchone()[0]

    conn.close()
    return {
        "moz_places_rows": len(places),
        "moz_places": places,
        "user_activity_candidates": user_activity,
        "moz_historyvisits_rows": historyvisits_count,
        "moz_inputhistory_rows": inputhistory_count,
        "moz_annos_rows": annos_count,
        "moz_keywords_rows": keywords_count,
    }


def analyze_cookies(db_path: Path) -> dict:
    if not db_path.exists():
        return {"error": "not found"}
    conn = _open_ro(db_path)
    cur = conn.cursor()
    cur.execute("SELECT host, name, creationTime, lastAccessed, expiry FROM moz_cookies")
    cookies = [
        {"host": h, "name": n, "creationTime": c, "lastAccessed": la, "expiry": e}
        for h, n, c, la, e in cur.fetchall()
    ]
    conn.close()
    return {"moz_cookies_rows": len(cookies), "moz_cookies": cookies}


def analyze_favicons(db_path: Path) -> dict:
    if not db_path.exists():
        return {"error": "not found"}
    conn = _open_ro(db_path)
    cur = conn.cursor()
    cur.execute("SELECT page_url FROM moz_pages_w_icons")
    pages = [r[0] for r in cur.fetchall()]
    conn.close()
    non_default = [p for p in pages if p not in DEFAULT_BOOKMARK_URLS]
    return {
        "pages_with_icons": len(pages),
        "pages": pages,
        "non_default_pages": non_default,
    }


def analyze_bookmark_backups(backups_dir: Path) -> dict:
    if not backups_dir.exists():
        return {"backups": []}
    try:
        import lz4.block
    except ImportError:
        return {"error": "lz4 package not installed (pip install lz4)"}

    results = []
    for backup in sorted(backups_dir.glob("*.jsonlz4")):
        data = backup.read_bytes()
        if data[:8] != b"mozLz40\0":
            results.append({"file": backup.name, "error": "bad magic header"})
            continue
        tree = json.loads(lz4.block.decompress(data[8:]))

        non_default = []

        def walk(node):
            uri = node.get("uri")
            if uri and uri not in DEFAULT_BOOKMARK_URLS:
                non_default.append({"title": node.get("title"), "uri": uri})
            for child in node.get("children", []):
                walk(child)

        walk(tree)
        results.append({"file": backup.name, "non_default_bookmarks": non_default})
    return {"backups": results}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("evidence_dir", type=Path, help="Directory with extracted profile files")
    parser.add_argument("--out", type=Path, default=None, help="Write JSON report to this path")
    args = parser.parse_args()

    evidence_dir: Path = args.evidence_dir
    if not evidence_dir.is_dir():
        print(f"error: {evidence_dir} is not a directory", file=sys.stderr)
        return 1

    report = {
        "evidence_dir": str(evidence_dir),
        "hash_verification": verify_hashes(evidence_dir),
        "places": analyze_places(evidence_dir / "places.sqlite"),
        "cookies": analyze_cookies(evidence_dir / "cookies.sqlite"),
        "favicons": analyze_favicons(evidence_dir / "favicons.sqlite"),
        "bookmark_backups": analyze_bookmark_backups(evidence_dir / "bookmarkbackups"),
    }

    custody = CustodyLog(evidence_dir / "custody_log_module_b.json")
    for fname in ("places.sqlite", "cookies.sqlite", "favicons.sqlite"):
        fpath = evidence_dir / fname
        if fpath.exists():
            custody.record(
                CustodyEntry(
                    artifact_path=str(fpath),
                    sha256=hash_file(fpath),
                    action="analyzed",
                    notes="recover_evidence.py disk artifact analysis",
                )
            )
    custody.save()

    # --- Summary ---
    places = report["places"]
    cookies = report["cookies"]
    favicons = report["favicons"]
    backups = report["bookmark_backups"].get("backups", [])

    print("=== TRANCE Module B — Disk Evidence Recovery Summary ===\n")

    hv = report["hash_verification"]
    mismatches = {k: v for k, v in hv.items() if v.get("status") == "MISMATCH"}
    expected_changes = {k: v for k, v in hv.items() if v.get("status", "").startswith("changed")}
    if mismatches:
        print(f"!! HASH MISMATCH on {len(mismatches)} file(s) — integrity compromised: {list(mismatches)}\n")
    elif hv:
        print(f"Hash verification: {len(hv)} file(s) checked, {len(hv) - len(expected_changes)} match.")
        if expected_changes:
            print(f"  ({len(expected_changes)} -shm/-wal file(s) changed as expected from read-only open: {list(expected_changes)})")
        print()
    else:
        print("Hash verification: no hashes.sha256 found, skipped.\n")

    print(f"places.sqlite: {places.get('moz_places_rows', 0)} URL entries, "
          f"{places.get('moz_historyvisits_rows', 0)} history visits, "
          f"{places.get('moz_inputhistory_rows', 0)} typed-URL entries, "
          f"{places.get('moz_annos_rows', 0)} annotations.")
    activity = places.get("user_activity_candidates", [])
    if activity:
        print(f"  -> {len(activity)} entries look like real user activity (non-default, visited/typed):")
        for e in activity:
            print(f"     {e['url']}  (visits={e['visit_count']}, typed={e['typed']}, last_visit={e['last_visit_date']})")
    else:
        print("  -> No entries beyond Tor Browser's default bookmark set. No recoverable browsing history.")

    print(f"\ncookies.sqlite: {cookies.get('moz_cookies_rows', 0)} cookies.")
    if cookies.get("moz_cookies"):
        for c in cookies["moz_cookies"]:
            print(f"     {c['host']}  {c['name']}")
    else:
        print("  -> No cookies recovered.")

    print(f"\nfavicons.sqlite: {favicons.get('pages_with_icons', 0)} pages with icons, "
          f"{len(favicons.get('non_default_pages', []))} non-default.")
    for p in favicons.get("non_default_pages", []):
        print(f"     {p}")

    print(f"\nbookmarkbackups/: {len(backups)} backup file(s) found.")
    for b in backups:
        nd = b.get("non_default_bookmarks", [])
        print(f"  {b['file']}: {len(nd)} non-default bookmark(s)")
        for item in nd:
            print(f"     {item['title']}  {item['uri']}")

    print()
    if not activity and not cookies.get("moz_cookies") and not favicons.get("non_default_pages") \
            and all(not b.get("non_default_bookmarks") for b in backups):
        print("CONCLUSION: This profile snapshot contains only Tor Browser's stock first-run\n"
              "defaults. No trace of user browsing survives in places.sqlite, cookies.sqlite,\n"
              "favicons.sqlite, or bookmark backups. This is consistent with Tor Browser's\n"
              "permanent-private-browsing default (history is kept in memory only, never\n"
              "written to disk, unless the user explicitly disables private browsing).")
    else:
        print("CONCLUSION: Evidence of user activity found above — review the flagged entries.")

    if args.out:
        args.out.write_text(json.dumps(report, indent=2, default=str))
        print(f"\nFull JSON report written to {args.out}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
