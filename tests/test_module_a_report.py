from modules.module_a_registry.report import build_context


def test_no_findings_gives_empty_sections():
    details = {
        "summary": "No Tor Browser artifacts found in the provided hives.",
        "errors": [],
        "custody_log_path": None,
        "findings_by_type": {},
        "hives_provided": {"ntuser": True, "system": False, "amcache": False},
    }
    ctx = build_context(details)
    assert ctx["sections"] == []
    assert ctx["total_findings"] == 0
    assert ctx["hives_analyzed"] == ["NTUSER.DAT"]
    assert ctx["hives_missing"] == ["SYSTEM", "Amcache.hve"]


def test_sections_ordered_strongest_confidence_first():
    details = {
        "summary": "x",
        "errors": [],
        "custody_log_path": None,
        "findings_by_type": {
            "RecentDocs": [
                {
                    "description": "d1",
                    "source": "NTUSER.DAT",
                    "timestamp": None,
                    "confidence": "low",
                }
            ],
            "ShimCache": [
                {
                    "description": "d2",
                    "source": "SYSTEM",
                    "timestamp": None,
                    "confidence": "medium",
                }
            ],
            "UserAssist": [
                {
                    "description": "d3",
                    "source": "NTUSER.DAT",
                    "timestamp": "t",
                    "confidence": "high",
                }
            ],
        },
        "hives_provided": {"ntuser": True, "system": True, "amcache": False},
    }
    ctx = build_context(details)
    types = [s["type"] for s in ctx["sections"]]
    assert types == ["UserAssist", "ShimCache", "RecentDocs"]
    assert ctx["total_findings"] == 3
    user_assist_section = next(s for s in ctx["sections"] if s["type"] == "UserAssist")
    assert user_assist_section["confidence"] == "high"
    shimcache_section = next(s for s in ctx["sections"] if s["type"] == "ShimCache")
    assert shimcache_section["confidence"] == "medium"


def test_errors_and_summary_passed_through():
    details = {
        "summary": "some summary",
        "errors": ["ShimCache (SYSTEM): bad hive"],
        "custody_log_path": "/tmp/x.json",
        "findings_by_type": {},
        "hives_provided": {"ntuser": False, "system": True, "amcache": False},
    }
    ctx = build_context(details)
    assert ctx["summary"] == "some summary"
    assert ctx["errors"] == ["ShimCache (SYSTEM): bad hive"]


def test_missing_optional_keys_degrade_gracefully():
    # A details dict without findings_by_type/hives_provided (e.g. hand-built) shouldn't crash.
    ctx = build_context({"summary": "x", "errors": []})
    assert ctx["sections"] == []
    assert ctx["hives_analyzed"] == []
    assert ctx["hives_missing"] == []


def test_exact_duplicate_findings_collapsed_with_occurrence_count():
    # Real bug: regipy's UserAssist extraction returned the same launch twice.
    dup = {
        "description": "UserAssist evidence for 'C:\\Tor Browser\\firefox.exe' (run_count=11). Confidence: HIGH.",
        "source": "NTUSER.DAT",
        "timestamp": "2026-09-18T07:14:09+00:00",
    }
    details = {
        "summary": "x",
        "errors": [],
        "findings_by_type": {"UserAssist": [dup, dict(dup), dict(dup)]},
        "hives_provided": {"ntuser": True, "system": False, "amcache": False},
    }
    ctx = build_context(details)
    section = ctx["sections"][0]
    assert len(section["findings"]) == 1
    assert section["findings"][0]["occurrences"] == 3
    assert ctx["total_findings"] == 1


def test_path_and_structured_fields_extracted_from_description():
    details = {
        "summary": "x",
        "errors": [],
        "findings_by_type": {
            "UserAssist": [
                {
                    "description": "UserAssist evidence for 'C:\\Tor Browser\\firefox.exe' (run_count=11, focus_count=2, total_focus_time_ms=500). Confidence: HIGH.",
                    "source": "NTUSER.DAT",
                    "timestamp": "2026-09-18T07:14:09+00:00",
                }
            ],
            "Amcache": [
                {
                    "description": "Amcache install/first-seen evidence for 'c:\\tor browser\\firefox.exe' (sha1=abc123, size=1024). Confidence: HIGH.",
                    "source": "Amcache.hve",
                    "timestamp": "2026-09-04T04:36:35+00:00",
                }
            ],
        },
        "hives_provided": {"ntuser": True, "system": False, "amcache": True},
    }
    ctx = build_context(details)
    ua = next(s for s in ctx["sections"] if s["type"] == "UserAssist")["findings"][0]
    assert ua["path"] == "C:\\Tor Browser\\firefox.exe"
    assert ua["run_count"] == 11
    assert ua["focus_count"] == 2
    assert ua["total_focus_time_ms"] == 500

    am = next(s for s in ctx["sections"] if s["type"] == "Amcache")["findings"][0]
    assert am["sha1"] == "abc123"
    assert am["size"] == 1024


def test_component_timeline_correlates_same_basename_across_hive_types():
    details = {
        "summary": "x",
        "errors": [],
        "findings_by_type": {
            "UserAssist": [
                {
                    "description": "UserAssist evidence for 'C:\\Tor Browser\\firefox.exe' (run_count=11, focus_count=0, total_focus_time_ms=0). Confidence: HIGH.",
                    "source": "NTUSER.DAT",
                    "timestamp": "2026-09-18T07:14:09+00:00",
                }
            ],
            "Amcache": [
                {
                    "description": "Amcache install/first-seen evidence for 'c:\\tor browser\\firefox.exe' (sha1=abc, size=1). Confidence: HIGH.",
                    "source": "Amcache.hve",
                    "timestamp": "2026-09-04T04:36:35+00:00",
                }
            ],
            "ShimCache": [
                {
                    "description": "ShimCache/AppCompatCache entry for 'C:\\Tor Browser\\firefox.exe'. Confidence: MEDIUM.",
                    "source": "SYSTEM",
                    "timestamp": "2026-09-03T07:48:23+00:00",
                }
            ],
            "RecentDocs": [
                {
                    "description": "RecentDocs entry 'unrelated.docx' — recently accessed file. Confidence: LOW.",
                    "source": "NTUSER.DAT",
                    "timestamp": "2026-09-10T00:00:00+00:00",
                }
            ],
        },
        "hives_provided": {"ntuser": True, "system": True, "amcache": True},
    }
    ctx = build_context(details)
    timeline = ctx["component_timeline"]
    firefox = next(c for c in timeline if c["basename"] == "firefox.exe")
    assert set(firefox["seen_in"]) == {"UserAssist", "Amcache", "ShimCache"}
    assert firefox["userassist_run_count"] == 11
    assert firefox["shimcache_hits"] == 1
    assert firefox["amcache_first_seen"] is not None

    # RecentDocs entry is unrelated -> its own single-source component, not merged in.
    doc = next(c for c in timeline if c["basename"] == "unrelated.docx")
    assert doc["seen_in"] == ["RecentDocs"]

    # Corroborated (2+ sources) sorts before single-source, and count is correct.
    assert timeline[0]["basename"] == "firefox.exe"
    assert ctx["corroborated_components"] == 1


def test_linked_launches_groups_same_timestamp_different_basenames():
    # Real pattern: a .lnk shortcut and the .exe it launched both get a UserAssist
    # entry with the identical recorded instant -- same event, not cross-hive
    # corroboration (both are UserAssist).
    details = {
        "summary": "x",
        "errors": [],
        "findings_by_type": {
            "UserAssist": [
                {
                    "description": "UserAssist evidence for 'E:\\Tor Browser\\Tor Browser.lnk' (run_count=1).",
                    "source": "NTUSER.DAT",
                    "timestamp": "2026-09-03T04:41:53.211000+00:00",
                },
                {
                    "description": "UserAssist evidence for 'E:\\Tor Browser\\Browser\\firefox.exe' (run_count=1).",
                    "source": "NTUSER.DAT",
                    "timestamp": "2026-09-03T04:41:53.211000+00:00",
                },
                {
                    "description": "UserAssist evidence for 'C:\\unrelated.exe' (run_count=1).",
                    "source": "NTUSER.DAT",
                    "timestamp": "2026-01-01T00:00:00+00:00",
                },
            ]
        },
        "hives_provided": {"ntuser": True, "system": False, "amcache": False},
    }
    ctx = build_context(details)
    assert len(ctx["linked_launches"]) == 1
    link = ctx["linked_launches"][0]
    assert link["timestamp"] == "2026-09-03T04:41:53.211000+00:00"
    assert link["paths"] == [
        "E:\\Tor Browser\\Browser\\firefox.exe",
        "E:\\Tor Browser\\Tor Browser.lnk",
    ]


def test_linked_launches_empty_when_no_shared_timestamps():
    details = {
        "summary": "x",
        "errors": [],
        "findings_by_type": {
            "UserAssist": [
                {
                    "description": "UserAssist evidence for 'a.exe' (run_count=1).",
                    "source": "NTUSER.DAT",
                    "timestamp": "2026-01-01T00:00:00+00:00",
                },
                {
                    "description": "UserAssist evidence for 'b.exe' (run_count=1).",
                    "source": "NTUSER.DAT",
                    "timestamp": "2026-01-02T00:00:00+00:00",
                },
            ]
        },
        "hives_provided": {"ntuser": True, "system": False, "amcache": False},
    }
    ctx = build_context(details)
    assert ctx["linked_launches"] == []


def test_quiet_hive_notes_flag_supplied_but_empty_amcache_and_shimcache():
    details = {
        "summary": "x",
        "errors": [],
        "findings_by_type": {
            "UserAssist": [
                {
                    "description": "UserAssist evidence for 'a.exe' (run_count=1).",
                    "source": "NTUSER.DAT",
                    "timestamp": "2026-01-01T00:00:00+00:00",
                }
            ]
        },
        "hives_provided": {"ntuser": True, "system": True, "amcache": True},
    }
    ctx = build_context(details)
    assert len(ctx["quiet_hive_notes"]) == 3
    assert any("Amcache" in note for note in ctx["quiet_hive_notes"])
    assert any("ShimCache" in note for note in ctx["quiet_hive_notes"])
    assert any("BAM" in note for note in ctx["quiet_hive_notes"])


def test_quiet_hive_notes_absent_when_hive_not_supplied_or_has_findings():
    details = {
        "summary": "x",
        "errors": [],
        "findings_by_type": {
            "ShimCache": [
                {
                    "description": "ShimCache/AppCompatCache entry for 'a.exe'.",
                    "source": "SYSTEM",
                    "timestamp": None,
                }
            ],
            "BAM": [
                {
                    "description": "BAM evidence for 'a.exe', sid=S-1-5-21-1.",
                    "source": "SYSTEM",
                    "timestamp": None,
                }
            ],
        },
        # amcache not supplied at all -> no note; system supplied and has findings for
        # both of its types (ShimCache, BAM) -> no note for either.
        "hives_provided": {"ntuser": False, "system": True, "amcache": False},
    }
    ctx = build_context(details)
    assert ctx["quiet_hive_notes"] == []


def test_component_timeline_empty_when_no_paths_extractable():
    details = {
        "summary": "x",
        "errors": [],
        "findings_by_type": {
            "RecentDocs": [
                {"description": "no quoted path here", "source": "NTUSER.DAT", "timestamp": None}
            ]
        },
        "hives_provided": {"ntuser": True, "system": False, "amcache": False},
    }
    ctx = build_context(details)
    assert ctx["component_timeline"] == []
    assert ctx["corroborated_components"] == 0


def test_bam_corroborates_userassist_and_gets_its_own_timeline_column():
    details = {
        "summary": "x",
        "errors": [],
        "findings_by_type": {
            "UserAssist": [
                {
                    "description": "UserAssist evidence for 'C:\\Tor Browser\\firefox.exe' (run_count=1).",
                    "source": "NTUSER.DAT",
                    "timestamp": "2026-07-14T14:15:22+00:00",
                }
            ],
            "BAM": [
                {
                    "description": "BAM evidence for 'c:\\tor browser\\firefox.exe', sid=S-1-5-21-1-2-3-1001.",
                    "source": "SYSTEM",
                    "timestamp": "2026-07-14T15:00:00+00:00",
                }
            ],
        },
        "hives_provided": {"ntuser": True, "system": True, "amcache": False},
    }
    ctx = build_context(details)
    component = ctx["component_timeline"][0]
    assert set(component["seen_in"]) == {"UserAssist", "BAM"}
    assert component["bam_last_run"] is not None
    assert ctx["corroborated_components"] == 1


def test_profiles_table_rendered_sorted_by_path():
    details = {
        "summary": "x",
        "errors": [],
        "findings_by_type": {},
        "hives_provided": {"ntuser": False, "system": False, "amcache": False},
        "profiles": [
            {"path": r"C:\Users\Zed", "sid": "S-1-5-21-1-2-3-1002", "last_write": None},
            {"path": r"C:\Users\Admin", "sid": "S-1-5-21-1-2-3-1001", "last_write": None},
        ],
    }
    ctx = build_context(details)
    assert [p["path"] for p in ctx["profiles"]] == [r"C:\Users\Admin", r"C:\Users\Zed"]


def test_profiles_table_empty_when_none_supplied():
    details = {
        "summary": "x",
        "errors": [],
        "findings_by_type": {},
        "hives_provided": {"ntuser": False, "system": False, "amcache": False},
    }
    ctx = build_context(details)
    assert ctx["profiles"] == []


def test_profile_matching_bam_sid_is_flagged_relevant():
    details = {
        "summary": "x",
        "errors": [],
        "findings_by_type": {
            "BAM": [
                {
                    "description": "BAM evidence for 'c:\\tor browser\\firefox.exe', "
                    "sid=S-1-5-21-1-2-3-1001.",
                    "source": "SYSTEM",
                    "timestamp": "2026-07-14T15:00:00+00:00",
                }
            ]
        },
        "hives_provided": {"ntuser": False, "system": True, "amcache": False},
        "profiles": [
            {"path": r"C:\Users\Admin", "sid": "S-1-5-21-1-2-3-1001", "last_write": None},
            {
                "path": r"C:\Windows\ServiceProfiles\LocalService",
                "sid": "S-1-5-19",
                "last_write": None,
            },
        ],
    }
    ctx = build_context(details)
    relevant = [p for p in ctx["profiles"] if p["is_relevant"]]
    other = [p for p in ctx["profiles"] if not p["is_relevant"]]
    assert [p["path"] for p in relevant] == [r"C:\Users\Admin"]
    assert [p["path"] for p in other] == [r"C:\Windows\ServiceProfiles\LocalService"]


def test_no_bam_sid_leaves_every_profile_unflagged():
    details = {
        "summary": "x",
        "errors": [],
        "findings_by_type": {},
        "hives_provided": {"ntuser": False, "system": False, "amcache": False},
        "profiles": [{"path": r"C:\Users\Admin", "sid": "S-1-5-21-1-2-3-1001", "last_write": None}],
    }
    ctx = build_context(details)
    assert ctx["profiles"][0]["is_relevant"] is False


def test_component_timeline_merges_last_activity_from_strongest_source():
    details = {
        "summary": "x",
        "errors": [],
        "findings_by_type": {
            "UserAssist": [
                {
                    "description": "UserAssist evidence for 'C:\\Tor Browser\\firefox.exe' "
                    "(run_count=1).",
                    "source": "NTUSER.DAT",
                    "timestamp": "2026-10-04T07:30:42+00:00",
                }
            ],
            "BAM": [
                {
                    "description": "BAM evidence for 'c:\\tor browser\\firefox.exe', "
                    "sid=S-1-5-21-1-2-3-1001.",
                    "source": "SYSTEM",
                    "timestamp": "2026-10-04T07:31:01+00:00",
                }
            ],
        },
        "hives_provided": {"ntuser": True, "system": True, "amcache": False},
    }
    ctx = build_context(details)
    component = ctx["component_timeline"][0]
    # BAM's timestamp is the later of the two -- last_activity must prefer it and say so.
    assert component["last_activity"]["source"] == "BAM"
    assert component["last_activity"]["timestamp"] == component["bam_last_run"]


def test_harddiskvolume_path_resolved_via_matching_drive_letter_in_another_record():
    details = {
        "summary": "x",
        "errors": [],
        "findings_by_type": {
            "UserAssist": [
                {
                    "description": "UserAssist evidence for 'E:\\Tor Browser\\Browser"
                    "\\firefox.exe' (run_count=1).",
                    "source": "NTUSER.DAT",
                    "timestamp": "2026-10-04T07:30:42+00:00",
                }
            ],
            "BAM": [
                {
                    "description": "BAM evidence for "
                    "'\\Device\\HarddiskVolume6\\Tor Browser\\Browser\\firefox.exe', "
                    "sid=S-1-5-21-1-2-3-1001.",
                    "source": "SYSTEM",
                    "timestamp": "2026-10-04T07:31:01+00:00",
                }
            ],
        },
        "hives_provided": {"ntuser": True, "system": True, "amcache": False},
    }
    ctx = build_context(details)
    bam_section = next(s for s in ctx["sections"] if s["type"] == "BAM")
    note = bam_section["findings"][0]["harddiskvolume_note"]
    assert "HarddiskVolume6" in note
    assert "E:" in note
    assert "inference" in note or "inferred" in note


def test_system_context_surfaces_context_findings_separately_from_sections():
    details = {
        "summary": "x",
        "errors": [],
        "findings_by_type": {
            "UserAssist": [
                {
                    "description": "UserAssist evidence for 'C:\\Tor Browser\\firefox.exe' "
                    "(run_count=1).",
                    "source": "NTUSER.DAT",
                    "timestamp": "2026-07-14T14:15:22+00:00",
                    "confidence": "high",
                }
            ],
            "ComputerName": [
                {
                    "description": "Computer name recorded as 'DESKTOP-ABC123'.",
                    "source": "SYSTEM",
                    "timestamp": None,
                    "confidence": "high",
                    "category": "context",
                    "computer_name": "DESKTOP-ABC123",
                }
            ],
        },
        "hives_provided": {"ntuser": True, "system": True, "amcache": False},
    }
    ctx = build_context(details)

    # Context findings never appear in the tor-direct `sections` list.
    assert {s["type"] for s in ctx["sections"]} == {"UserAssist"}
    assert "ComputerName" in ctx["system_context"]
    assert ctx["system_context"]["ComputerName"]["computer_name"] == "DESKTOP-ABC123"


def test_system_context_empty_when_no_context_findings():
    details = {
        "summary": "x",
        "errors": [],
        "findings_by_type": {},
        "hives_provided": {"ntuser": False, "system": False, "amcache": False},
    }
    ctx = build_context(details)
    assert ctx["system_context"] == {}


def test_harddiskvolume_path_with_no_matching_letter_states_so_honestly():
    details = {
        "summary": "x",
        "errors": [],
        "findings_by_type": {
            "BAM": [
                {
                    "description": "BAM evidence for "
                    "'\\Device\\HarddiskVolume6\\Tor Browser\\Browser\\firefox.exe', "
                    "sid=S-1-5-21-1-2-3-1001.",
                    "source": "SYSTEM",
                    "timestamp": "2026-10-04T07:31:01+00:00",
                }
            ],
        },
        "hives_provided": {"ntuser": False, "system": True, "amcache": False},
    }
    ctx = build_context(details)
    bam_section = next(s for s in ctx["sections"] if s["type"] == "BAM")
    note = bam_section["findings"][0]["harddiskvolume_note"]
    assert "HarddiskVolume6" in note
    assert "could not be determined" in note
