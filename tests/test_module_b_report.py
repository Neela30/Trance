import json

from findings import build_findings
from core.config import TranceConfig
from core.schema import ModuleResult
from modules.module_b_disk.analyze_tor_datadir import parse_state
from modules.module_b_disk.report import build_context
from report import render_report


def _details():
    return {
        "profile": {
            "evidence_dir": "/ev/profile",
            "analysis_status": "ok",
            "integrity": {
                "manifest_status": "verified",
                "source_unchanged": True,
                "source_sha256": {"a": "1"},
            },
            "places": {
                "moz_places_rows": 9,
                "moz_places": [{"default_profile_entry": True}] * 8
                + [{"default_profile_entry": False}],
                "user_activity_candidates": [
                    {
                        "url": "http://x.onion/p",
                        "title": "P",
                        "visit_count": 2,
                        "typed": 1,
                        "last_visit_date": 1_789_805_084_000_000,
                    }
                ],
                "moz_historyvisits_rows": 2,
                "downloads": [
                    {
                        "source_url": "http://x.onion/f",
                        "destination_file_uri": "file:///C:/f.txt",
                        "date_added": 1_789_805_084_000_000,
                    }
                ],
            },
            "cookies": {
                "moz_cookies": [
                    {
                        "host": "x.onion",
                        "name": "s",
                        "creationTime": 1_789_805_084_000_000,
                        "lastAccessed": None,
                        "expiry": 1_789_891_484,
                    }
                ]
            },
            "favicons": {"non_default_pages": ["http://x.onion/p"]},
            "bookmark_backups": {
                "backups": [
                    {
                        "file": "b.jsonlz4",
                        "non_default_bookmarks": [{"title": "T", "uri": "http://x.onion/"}],
                    }
                ]
            },
        },
        "tor_daemon": {
            "tor_data_dir": "/ev/Tor",
            "analysis_status": "ok",
            "integrity": {
                "manifest_status": "absent",
                "source_unchanged": True,
                "source_sha256": {"state": "1", "lock": "2"},
            },
            "daemon_start_utc": "2026-09-19T07:43:51+00:00",
            "state": {
                "tor_version": "Tor 0.4.9.11",
                "last_written_utc": "2026-09-19 08:32:51",
                "generated_guest_local": "2026-09-19 01:32:51",
                "guest_utc_offset_hours": -7.0,
                "minutes_since_user_activity": "3",
                "dormant": "0",
                "total_circuits_built": "170",
                "histogram_consistent": True,
                "guards_sampled": 24,
                "guards_used": [
                    {
                        "nickname": "G",
                        "rsa_id": "AB",
                        "confirmed_on": "2026-08-25T08:38:55",
                        "use_attempts": "5.000000",
                        "use_successes": "5.000000",
                        "circuit_attempts": "53.000000",
                        "circuit_successes": "53.000000",
                    }
                ],
            },
            "consensus": {
                "valid_after_utc": "2026-09-19 07:00:00",
                "fresh_until_utc": "2026-09-19 08:00:00",
                "valid_until_utc": "2026-09-19 10:00:00",
                "file_mtime_utc": "2026-09-19T07:44:05+00:00",
            },
            "onion_auth": {
                "credentials": [
                    {
                        "onion_address": "a" * 56 + ".onion",
                        "filename": "a.auth_private",
                        "mtime_utc": "2026-09-19T07:46:07+00:00",
                        "sha256": "9" * 64,
                    }
                ],
                "ignored_files": [{"filename": "notes.txt"}],
            },
        },
        "downloads": {
            "volume_root": "/mnt/vol",
            "files_walked": 124769,
            "scan_seconds": 5.3,
            "xattr_support": True,
            "tor_daemon_window": {
                "start_utc": "2026-09-19T07:43:51+00:00",
                "end_utc": "2026-09-19T08:32:51+00:00",
            },
            "note": "n",
            "internet_origin_files": [
                {
                    "path": "Users/u/Downloads/a.txt",
                    "size": 942,
                    "sha256": "e" * 64,
                    "zone_identifier": {"zone_id": 3, "host_url": None, "referrer_url": None},
                    "timestamps": {
                        "source": "ntfs",
                        "created_utc": "2026-09-19T08:12:26+00:00",
                        "modified_utc": "2026-09-19T08:12:27+00:00",
                    },
                    "within_tor_daemon_window": True,
                },
                {
                    "path": "Users/u/Desktop/b.exe",
                    "size": 5,
                    "sha256": "f" * 64,
                    "zone_identifier": {
                        "zone_id": 3,
                        "host_url": "http://h/",
                        "referrer_url": None,
                    },
                    "timestamps": {
                        "source": "stat",
                        "created_utc": None,
                        "modified_utc": "2026-09-20T08:12:26+00:00",
                    },
                    "within_tor_daemon_window": False,
                },
            ],
        },
    }


def test_context_shapes_every_section():
    ctx = build_context(_details())
    assert ctx["supplied"] == ["profile", "tor_daemon", "downloads"]
    assert ctx["errors"] == {}
    profile = ctx["profile"]
    assert profile["inert"] is False
    assert profile["default_entries"] == 8
    assert profile["history"][0]["last_visit"] == "2026-09-19 08:04:44 UTC"
    assert profile["download_records"][0]["destination"] == "file:///C:/f.txt"
    assert profile["cookies"][0]["expires"] == "2026-09-20 08:04:44 UTC"
    assert profile["bookmarks"] == [{"file": "b.jsonlz4", "title": "T", "uri": "http://x.onion/"}]
    daemon = ctx["daemon"]
    assert daemon["daemon_start"] == "2026-09-19 07:43:51 UTC"
    assert daemon["state_written"] == "2026-09-19 08:32:51 UTC"
    assert daemon["minutes_since_user_activity"] == 3
    assert daemon["guards_used"][0]["use"] == "5/5"
    assert daemon["guards_used"][0]["circuits"] == "53/53"
    assert daemon["consensus"]["valid_after"] == "2026-09-19 07:00:00 UTC"
    assert daemon["credentials"][0]["onion_address"].endswith(".onion")
    assert daemon["ignored_auth_files"] == ["notes.txt"]
    downloads = ctx["downloads"]
    assert (downloads["inside"], downloads["outside"], downloads["unknown"]) == (1, 1, 0)
    assert downloads["window"] == {
        "start": "2026-09-19 07:43:51 UTC",
        "end": "2026-09-19 08:32:51 UTC",
    }
    assert downloads["hits"][0]["created"] == "2026-09-19 08:12:26 UTC"
    assert downloads["hits"][1]["created"] is None
    assert downloads["any_url_fields"] is True
    assert ctx["carve"] is None


def test_inert_profile_and_failed_sections():
    details = _details()
    details["profile"]["places"]["user_activity_candidates"] = []
    details["profile"]["cookies"]["moz_cookies"] = []
    details["profile"]["bookmark_backups"]["backups"] = []
    details["profile"]["favicons"] = {"error": "not found"}
    details["tor_daemon"] = {"error": "IntegrityError: boom"}
    details["downloads"]["tor_daemon_window"] = None
    for hit in details["downloads"]["internet_origin_files"]:
        hit["within_tor_daemon_window"] = None
    ctx = build_context(details)
    assert ctx["profile"]["inert"] is True
    assert ctx["profile"]["errors"] == {"favicons.sqlite": "not found"}
    assert ctx["daemon"] is None
    assert ctx["errors"] == {"tor_daemon": "IntegrityError: boom"}
    assert ctx["downloads"]["window"] is None
    assert ctx["downloads"]["unknown"] == 2


def test_report_renders_module_b_section(tmp_path):
    config = TranceConfig("case", tmp_path)
    result = ModuleResult(module="module_b_disk", status="ok", artifacts=[], details=_details())
    html = render_report(build_findings(config, [result]))
    assert "Disk — Tor Browser profile, Tor daemon &amp; downloaded files" in html
    assert "Internet-origin files" in html
    assert "Users/u/Downloads/a.txt" in html
    assert "Tor Browser deliberately omits" in html
    assert "Entry guards that carried traffic" in html
    assert 'class="chip high">yes' in html
    assert 'class="chip low">no' in html
    assert "showing 2 of 2" not in html  # no generic fallback table for B


def test_report_falls_back_to_generic_table_when_module_b_errors(tmp_path):
    config = TranceConfig("case", tmp_path)
    result = ModuleResult(
        module="module_b_disk", status="error", artifacts=[], details={}, message="x"
    )
    html = render_report(build_findings(config, [result]))
    assert "Internet-origin files" not in html
    assert "module_b_disk" in html


def test_histogram_check_accounts_for_abandoned_circuits(tmp_path):
    state = tmp_path / "state"
    state.write_text(
        "TorVersion Tor 0.4.9.11\nLastWritten 2026-09-19 08:32:51\n"
        "TotalBuildTimes 170\nCircuitBuildAbandonedCount 1\n"
        "CircuitBuildTimeBin 500 100\nCircuitBuildTimeBin 600 69\n"
    )
    parsed = parse_state(state)
    assert parsed["build_time_histogram_total"] == 169
    assert parsed["circuits_abandoned"] == 1
    assert parsed["histogram_consistent"] is True
    state.write_text(
        state.read_text().replace("CircuitBuildTimeBin 600 69", "CircuitBuildTimeBin 600 60")
    )
    assert parse_state(state)["histogram_consistent"] is False


def test_findings_json_round_trip_preserves_presenter_input(tmp_path):
    config = TranceConfig("case", tmp_path)
    result = ModuleResult(module="module_b_disk", status="ok", artifacts=[], details=_details())
    findings = json.loads(json.dumps(build_findings(config, [result])))
    assert "Users/u/Downloads/a.txt" in render_report(findings)


def _residue_and_ntfs_details():
    details = _details()
    details["memory_residue"] = {
        "volume_root": "/mnt/vol",
        "hibernation_present": True,
        "onion_addresses": {"b" * 56 + ".onion": {"occurrences": 4, "files": ["hiberfil.sys"]}},
        "files": [
            {
                "kind": "pagefile",
                "path": "pagefile.sys",
                "size": 10,
                "modified_utc": "2026-09-02T02:30:00+00:00",
                "compressed": False,
                "onion_addresses": {},
                "client_auth_credentials": [],
                "tor_markers": {},
            },
            {
                "kind": "hibernation",
                "path": "hiberfil.sys",
                "size": 20,
                "modified_utc": "2026-09-19T08:40:00+00:00",
                "compressed": True,
                "onion_addresses": {"b" * 56 + ".onion": {"occurrences": 4}},
                "client_auth_credentials": [{"onion_address": "c" * 56 + ".onion"}],
                "tor_markers": {"tor_state": {"occurrences": 2}},
            },
        ],
    }
    details["ntfs"] = {
        "sources": {"mft": "/mnt/vol/$MFT", "usnjrnl": "/mnt/vol/$Extend/$UsnJrnl:$J"},
        "mft": {
            "records": 1000,
            "in_use": 900,
            "onion_filenames": [],
            "zone_identifier_streams": [
                {
                    "path": "Users\\u\\Downloads\\gone.txt",
                    "record": 81,
                    "deleted": True,
                    "created_utc": "2026-09-19T08:12:00+00:00",
                    "zone_identifier": {"zone_id": 3},
                },
                {
                    "path": "Users\\u\\Downloads\\live.txt",
                    "record": 82,
                    "deleted": False,
                    "created_utc": "2026-09-19T08:13:00+00:00",
                    "zone_identifier": {"zone_id": 3},
                },
            ],
            "resident_onion_strings": [
                {"path": "ONION_IN.TXT", "deleted": False, "onion_addresses": ["d" * 56 + ".onion"]}
            ],
            "deleted_tor_files": [{"path": "Tor Browser\\state", "modified_utc": None}],
        },
        "usnjrnl": {
            "records": 5000,
            "journal_first_utc": "2026-09-01T00:00:00+00:00",
            "journal_last_utc": "2026-09-19T09:00:00+00:00",
            "tor_activity_window": {
                "first_utc": "2026-09-19T07:44:00+00:00",
                "last_utc": "2026-09-19T08:31:00+00:00",
                "events": 2,
            },
            "tor_events": [
                {
                    "time_utc": "2026-09-19T07:44:00+00:00",
                    "path": "Tor Browser\\state",
                    "reasons": ["DATA_EXTEND", "CLOSE"],
                }
            ],
            "downloads": [],
        },
        "onion_addresses": {"a" * 56 + ".onion": {"sources": ["mft", "usnjrnl"], "deleted": True}},
    }
    return details


def test_residue_and_ntfs_context():
    ctx = build_context(_residue_and_ntfs_details())
    assert ctx["supplied"] == ["profile", "tor_daemon", "downloads", "memory_residue", "ntfs"]
    residue = ctx["residue"]
    assert residue["any_hits"] is True and residue["hibernation_present"] is True
    assert residue["files"][1]["compressed"] is True
    assert residue["files"][1]["markers"] == ["tor_state"]
    assert residue["addresses"][0]["files"] == ["hiberfil.sys"]
    ntfs = ctx["ntfs"]
    assert ntfs["mft_records"] == 1000 and ntfs["usn_records"] == 5000
    assert [d["path"] for d in ntfs["deleted_downloads"]] == ["Users\\u\\Downloads\\gone.txt"]
    assert ntfs["addresses"][0]["deleted"] is True
    assert ntfs["window"]["events"] == 2
    assert ntfs["events"][0]["reasons"] == "data extend, close"


def test_ntfs_unavailable_is_a_note_not_an_error():
    details = _details()
    details["ntfs"] = {"error": "no $MFT or $UsnJrnl:$J found; mount with show_sys_files"}
    ctx = build_context(details)
    assert ctx["errors"] == {}
    assert "show_sys_files" in ctx["notes"]["ntfs"]
    assert ctx["ntfs"] is None


def test_report_renders_residue_and_ntfs_sections(tmp_path):
    config = TranceConfig("case", tmp_path)
    result = ModuleResult(
        module="module_b_disk", status="ok", artifacts=[], details=_residue_and_ntfs_details()
    )
    html = render_report(build_findings(config, [result]))
    assert "Memory residue on disk" in html
    assert "hiberfil.sys" in html and "compressed — lower bound" in html
    assert "NTFS metadata" in html
    assert "Deleted internet-origin files" in html
    assert "gone.txt" in html and "live.txt" not in html
    assert "examiner's own transfer files" in html
    details = _details()
    details["ntfs"] = {"error": "no $MFT or $UsnJrnl:$J found; mount with show_sys_files"}
    html = render_report(
        build_findings(
            config,
            [ModuleResult(module="module_b_disk", status="ok", artifacts=[], details=details)],
        )
    )
    assert "Not analyzed" in html and "Remount the volume" in html
