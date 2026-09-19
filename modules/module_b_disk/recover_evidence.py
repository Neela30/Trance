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
import shutil
import sqlite3
import sys
import tempfile
from contextlib import contextmanager
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from core.custody_log import CustodyEntry, CustodyLog
from core.exceptions import IntegrityError
from core.hashing import hash_file
from modules.module_b_disk.evidence import external_output, working_copy

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


@contextmanager
def _open_ro(path: Path):
    """Open a disposable database + WAL/SHM copy, even for direct parser callers."""
    with tempfile.TemporaryDirectory(prefix="trance-sqlite-") as directory:
        target = Path(directory) / path.name
        for suffix in ("", "-wal", "-shm"):
            source = path.with_name(path.name + suffix)
            if source.is_symlink():
                raise IntegrityError(f"Database input must not be a symbolic link: {source}")
            if source.exists():
                shutil.copyfile(source, target.with_name(target.name + suffix))
        conn = sqlite3.connect(target.resolve().as_uri() + "?mode=ro", uri=True)
        try:
            yield conn
        finally:
            conn.close()


def analyze_places(db_path: Path) -> dict:
    if not db_path.exists():
        return {"error": "not found"}
    with _open_ro(db_path) as conn:
        cur = conn.cursor()

        cur.execute(
            "SELECT id, url, title, visit_count, hidden, typed, last_visit_date " "FROM moz_places"
        )
        places = []
        user_activity = []
        for row in cur.fetchall():
            pid, url, title, visit_count, _hidden, typed, last_visit_date = row
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

        cur.execute(
            "SELECT a.place_id, p.url, attr.name, a.content, a.dateAdded, a.lastModified "
            "FROM moz_annos a "
            "JOIN moz_anno_attributes attr ON attr.id = a.anno_attribute_id "
            "JOIN moz_places p ON p.id = a.place_id"
        )
        downloads = []
        for place_id, url, attr_name, content, date_added, last_modified in cur.fetchall():
            if attr_name == "downloads/destinationFileURI":
                downloads.append(
                    {
                        "place_id": place_id,
                        "source_url": url,
                        "destination_file_uri": content,
                        "date_added": date_added,
                        "last_modified": last_modified,
                    }
                )
        cur.execute("SELECT COUNT(*) FROM moz_annos")
        annos_count = cur.fetchone()[0]

        cur.execute("SELECT COUNT(*) FROM moz_keywords")
        keywords_count = cur.fetchone()[0]

    return {
        "moz_places_rows": len(places),
        "moz_places": places,
        "user_activity_candidates": user_activity,
        "moz_historyvisits_rows": historyvisits_count,
        "moz_inputhistory_rows": inputhistory_count,
        "moz_annos_rows": annos_count,
        "downloads": downloads,
        "moz_keywords_rows": keywords_count,
    }


def analyze_cookies(db_path: Path) -> dict:
    if not db_path.exists():
        return {"error": "not found"}
    with _open_ro(db_path) as conn:
        cur = conn.cursor()
        cur.execute("SELECT host, name, creationTime, lastAccessed, expiry FROM moz_cookies")
        cookies = [
            {"host": h, "name": n, "creationTime": c, "lastAccessed": la, "expiry": e}
            for h, n, c, la, e in cur.fetchall()
        ]
    return {"moz_cookies_rows": len(cookies), "moz_cookies": cookies}


def analyze_favicons(db_path: Path) -> dict:
    if not db_path.exists():
        return {"error": "not found"}
    with _open_ro(db_path) as conn:
        cur = conn.cursor()
        cur.execute("SELECT page_url FROM moz_pages_w_icons")
        pages = [r[0] for r in cur.fetchall()]
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


def analyze_profile(evidence_dir: Path) -> dict:
    """Analyze a verified snapshot and retain source hashes, never temporary paths."""
    with working_copy(evidence_dir) as (copy, hashes, verification):
        report = {
            "evidence_dir": str(evidence_dir.resolve()),
            "hash_verification": verification,
            "integrity": {
                "manifest_status": "verified" if verification else "absent",
                "unmanifested_files": sorted(set(hashes) - set(verification) - {"hashes.sha256"}),
                "source_sha256": hashes,
                "source_unchanged": False,
            },
        }
        for section, parser, name in (
            ("places", analyze_places, "places.sqlite"),
            ("cookies", analyze_cookies, "cookies.sqlite"),
            ("favicons", analyze_favicons, "favicons.sqlite"),
            ("bookmark_backups", analyze_bookmark_backups, "bookmarkbackups"),
        ):
            try:
                report[section] = parser(copy / name)
            except Exception as exc:
                report[section] = {"error": f"{type(exc).__name__}: {exc}"}
        report["analysis_status"] = (
            "incomplete"
            if any(
                report[k].get("error") or any(b.get("error") for b in report[k].get("backups", []))
                for k in ("places", "cookies", "favicons", "bookmark_backups")
            )
            else "ok"
        )
    report["integrity"]["source_unchanged"] = True
    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "evidence_dir", type=Path, help="Static directory of acquired profile files"
    )
    parser.add_argument("--out", type=Path, help="New JSON report path outside evidence")
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("output/module-b"),
        help="Parent for a new run directory when --out is omitted",
    )
    args = parser.parse_args(argv)
    if not args.evidence_dir.is_dir():
        print(f"error: {args.evidence_dir} is not a directory", file=sys.stderr)
        return 1
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    requested = args.out or args.output_dir / stamp / "recovery_report.json"
    try:
        output = external_output(requested, args.evidence_dir)
        custody_path = external_output(
            output.with_name(output.stem + ".custody.json"), args.evidence_dir
        )
        report = analyze_profile(args.evidence_dir)
        custody = CustodyLog(custody_path)
        for name, digest in report["integrity"]["source_sha256"].items():
            custody.record(
                CustodyEntry(
                    artifact_path=str(args.evidence_dir.resolve() / name),
                    sha256=digest,
                    action="verified_and_copied",
                    notes="Source hashed before/after analysis; parsers used disposable copies",
                )
            )
        output.parent.mkdir(parents=True, exist_ok=True)
        with output.open("x", encoding="utf-8") as stream:
            json.dump(report, stream, indent=2)
        custody.record(
            CustodyEntry(artifact_path=str(output), sha256=hash_file(output), action="generated")
        )
        with custody_path.open("x", encoding="utf-8") as stream:
            json.dump([asdict(entry) for entry in custody.entries], stream, indent=2)
    except (OSError, ValueError, IntegrityError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    print("=== TRANCE Module B — Disk Evidence Recovery ===")
    print(f"Analysis: {report['analysis_status']}")
    print(f"Acquisition manifest: {report['integrity']['manifest_status']}")
    print(f"Source files unchanged: {report['integrity']['source_unchanged']}")
    for section in ("places", "cookies", "favicons", "bookmark_backups"):
        result = report[section]
        print(f"{section}: {result.get('error', 'parsed; see report for findings')}")
    if report["analysis_status"] == "incomplete":
        print(
            "Analysis incomplete: missing or unreadable artifacts cannot establish absence of activity."
        )
    print(f"Report: {output}")
    print(f"Custody: {custody_path}")
    return 2 if report["analysis_status"] == "incomplete" else 0


if __name__ == "__main__":
    raise SystemExit(main())
