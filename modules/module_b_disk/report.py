"""Module B's contribution to the case report: shape disk `details` for the template.

Renders nothing itself (root-level report.py owns the template); it turns what
__init__.py's run() stored under details.profile / tor_daemon / downloads /
raw_carve into flat, display-ready structures. Two presentation rules matter:

  - Absence must read as absence-by-design where that is what it is. A Tor
    Browser profile records no history, downloads or cookies in
    permanent-private-browsing mode, so an empty history table is the expected
    result, not evidence that nothing happened. The template says so.
  - Caveats are printed once per section, not once per row. The artifact
    descriptions repeat them for findings.json consumers; the report reads them
    a single time in a ribbon.
"""

from __future__ import annotations

import datetime as dt

PRTIME_UNITS_PER_SECOND = 1_000_000


def _iso(value: str | None) -> str | None:
    if not value:
        return None
    try:
        parsed = dt.datetime.fromisoformat(value)
    except ValueError:
        return value
    if parsed.tzinfo:
        parsed = parsed.astimezone(dt.timezone.utc)
    return parsed.strftime("%Y-%m-%d %H:%M:%S UTC")


def _prtime(value: int | None) -> str | None:
    if not value:
        return None
    moment = dt.datetime.fromtimestamp(value / PRTIME_UNITS_PER_SECOND, dt.timezone.utc)
    return moment.strftime("%Y-%m-%d %H:%M:%S UTC")


def _epoch_seconds(value: int | None) -> str | None:
    if not value:
        return None
    return dt.datetime.fromtimestamp(value, dt.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def _integrity(section: dict) -> dict:
    integrity = section.get("integrity", {})
    return {
        "manifest_status": integrity.get("manifest_status", "absent"),
        "source_unchanged": integrity.get("source_unchanged"),
        "hashed_files": len(integrity.get("source_sha256", {})),
        "unmanifested_files": integrity.get("unmanifested_files", []),
    }


def _profile_context(profile: dict) -> dict:
    places = profile.get("places", {})
    cookies = profile.get("cookies", {})
    favicons = profile.get("favicons", {})
    backups = profile.get("bookmark_backups", {})
    history = [
        {
            "url": p["url"],
            "title": p.get("title"),
            "visit_count": p.get("visit_count") or 0,
            "typed": bool(p.get("typed")),
            "last_visit": _prtime(p.get("last_visit_date")),
        }
        for p in places.get("user_activity_candidates", [])
    ]
    default_entries = sum(1 for p in places.get("moz_places", []) if p.get("default_profile_entry"))
    bookmarks = [
        {"file": b.get("file"), "title": item.get("title"), "uri": item.get("uri")}
        for b in backups.get("backups", [])
        for item in b.get("non_default_bookmarks", [])
    ]
    errors = {
        name: section["error"]
        for name, section in (
            ("places.sqlite", places),
            ("cookies.sqlite", cookies),
            ("favicons.sqlite", favicons),
            ("bookmarkbackups", backups),
        )
        if section.get("error")
    }
    return {
        "evidence_dir": profile.get("evidence_dir"),
        "analysis_status": profile.get("analysis_status"),
        "integrity": _integrity(profile),
        "history": history,
        "places_rows": places.get("moz_places_rows", 0),
        "default_entries": default_entries,
        "history_visits": places.get("moz_historyvisits_rows", 0),
        "download_records": [
            {
                "source_url": d["source_url"],
                "destination": d["destination_file_uri"],
                "added": _prtime(d.get("date_added")),
            }
            for d in places.get("downloads", [])
        ],
        "cookies": [
            {
                "host": c["host"],
                "name": c["name"],
                "created": _prtime(c.get("creationTime")),
                "last_accessed": _prtime(c.get("lastAccessed")),
                "expires": _epoch_seconds(c.get("expiry")),
            }
            for c in cookies.get("moz_cookies", [])
        ],
        "favicon_pages": favicons.get("non_default_pages", []),
        "bookmarks": bookmarks,
        "errors": errors,
        "inert": not (history or bookmarks or cookies.get("moz_cookies")),
    }


def _daemon_context(daemon: dict) -> dict:
    state = daemon.get("state", {})
    consensus = daemon.get("consensus", {})
    auth = daemon.get("onion_auth", {})
    guards = [
        {
            "nickname": g.get("nickname"),
            "rsa_id": g.get("rsa_id"),
            "confirmed_on": _iso(g.get("confirmed_on")),
            "use": f"{_num(g.get('use_successes'))}/{_num(g.get('use_attempts'))}",
            "circuits": f"{_num(g.get('circuit_successes'))}/{_num(g.get('circuit_attempts'))}",
        }
        for g in state.get("guards_used", [])
    ]
    credentials = [
        {
            "onion_address": c.get("onion_address"),
            "filename": c.get("filename"),
            "modified": _iso(c.get("mtime_utc")),
            "sha256": c.get("sha256"),
        }
        for c in auth.get("credentials", [])
    ]
    idle = state.get("minutes_since_user_activity")
    return {
        "tor_data_dir": daemon.get("tor_data_dir"),
        "analysis_status": daemon.get("analysis_status"),
        "integrity": _integrity(daemon),
        "tor_version": state.get("tor_version"),
        "daemon_start": _iso(daemon.get("daemon_start_utc")),
        "state_written": _iso(state.get("last_written_utc")),
        "guest_local_written": state.get("generated_guest_local"),
        "guest_utc_offset_hours": state.get("guest_utc_offset_hours"),
        "minutes_since_user_activity": int(idle) if idle and idle.isdigit() else None,
        "dormant": state.get("dormant"),
        "circuits_built": state.get("total_circuits_built"),
        "histogram_consistent": state.get("histogram_consistent"),
        "guards_used": guards,
        "guards_sampled": state.get("guards_sampled", 0),
        "consensus": (
            None
            if consensus.get("error")
            else {
                "valid_after": _iso(consensus.get("valid_after_utc")),
                "fresh_until": _iso(consensus.get("fresh_until_utc")),
                "valid_until": _iso(consensus.get("valid_until_utc")),
                "fetched": _iso(consensus.get("file_mtime_utc")),
            }
        ),
        "credentials": credentials,
        "ignored_auth_files": [f.get("filename") for f in auth.get("ignored_files", [])],
        "errors": {
            name: section["error"]
            for name, section in (("state", state), ("consensus", consensus), ("onion-auth", auth))
            if section.get("error")
        },
    }


def _num(value: str | None) -> str:
    if value is None:
        return "?"
    try:
        return str(int(float(value)))
    except ValueError:
        return value


def _downloads_context(scan: dict) -> dict:
    hits = [
        {
            "path": h["path"],
            "size": h["size"],
            "sha256": h["sha256"],
            "zone_id": h["zone_identifier"].get("zone_id"),
            "host_url": h["zone_identifier"].get("host_url"),
            "referrer_url": h["zone_identifier"].get("referrer_url"),
            "created": _iso(h["timestamps"].get("created_utc")),
            "modified": _iso(h["timestamps"].get("modified_utc")),
            "timestamp_source": h["timestamps"].get("source"),
            "within_window": h.get("within_tor_daemon_window"),
        }
        for h in scan.get("internet_origin_files", [])
    ]
    window = scan.get("tor_daemon_window")
    return {
        "volume_root": scan.get("volume_root"),
        "files_walked": scan.get("files_walked", 0),
        "scan_seconds": scan.get("scan_seconds"),
        "xattr_support": scan.get("xattr_support"),
        "window": (
            {"start": _iso(window["start_utc"]), "end": _iso(window["end_utc"])} if window else None
        ),
        "hits": hits,
        "inside": sum(1 for h in hits if h["within_window"] is True),
        "outside": sum(1 for h in hits if h["within_window"] is False),
        "unknown": sum(1 for h in hits if h["within_window"] is None),
        "any_url_fields": any(h["host_url"] or h["referrer_url"] for h in hits),
        "note": scan.get("note"),
    }


def _carve_context(carve: dict) -> dict:
    return {
        "image": carve.get("image"),
        "image_sha256": carve.get("image_sha256"),
        "addresses": [
            {
                "address": address,
                "occurrences": hit.get("occurrences"),
                "first_offsets": hit.get("first_offsets", []),
            }
            for address, hit in carve.get("onion_addresses", {}).items()
        ],
        "credentials": [c.get("onion_address") for c in carve.get("client_auth_credentials", [])],
    }


def build_context(details: dict) -> dict:
    sections = {}
    errors = {}
    for name, builder in (
        ("profile", _profile_context),
        ("tor_daemon", _daemon_context),
        ("downloads", _downloads_context),
        ("raw_carve", _carve_context),
    ):
        section = details.get(name)
        if section is None:
            continue
        if section.get("error"):
            errors[name] = section["error"]
            continue
        sections[name] = builder(section)
    supplied = [
        name for name in ("profile", "tor_daemon", "downloads", "raw_carve") if name in details
    ]
    return {
        "supplied": supplied,
        "errors": errors,
        "profile": sections.get("profile"),
        "daemon": sections.get("tor_daemon"),
        "downloads": sections.get("downloads"),
        "carve": sections.get("raw_carve"),
    }
