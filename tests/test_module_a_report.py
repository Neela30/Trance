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


def test_muicache_timestamp_never_contaminates_execution_timing_fields():
    """MUICache's own timestamp is a registry key's shared last-write time, not a
    per-program run time (Fix 4) -- it must never leak into amcache_first_seen/
    userassist_last_run/bam_last_run/last_activity, even when it's the most recent
    timestamp present for a component. Uses a MUICache timestamp far in the future of the
    real UserAssist/BAM activity to prove it's never picked up by a naive "most recent"
    computation."""
    details = {
        "summary": "x",
        "errors": [],
        "findings_by_type": {
            "UserAssist": [
                {
                    "description": "UserAssist evidence for 'E:\\Tor Browser\\firefox.exe' "
                    "(run_count=3).",
                    "source": "NTUSER.DAT",
                    "timestamp": "2026-07-14T14:15:22+00:00",
                }
            ],
            "BAM": [
                {
                    "description": "BAM evidence for 'E:\\Tor Browser\\firefox.exe', "
                    "sid=S-1-5-21-1-2-3-1001.",
                    "source": "SYSTEM",
                    "timestamp": "2026-07-14T14:15:30+00:00",
                }
            ],
            "MUICache": [
                {
                    "description": "MUICache entry for 'E:\\Tor Browser\\firefox.exe' "
                    "— 'Tor Browser', Mozilla Corporation.",
                    "source": "NTUSER.DAT",
                    # Registry key last-write, far after the real activity -- must never
                    # be picked up as "last activity" or any other execution-timing field.
                    "timestamp": "2026-12-01T00:00:00+00:00",
                }
            ],
        },
        "hives_provided": {"ntuser": True, "system": True, "amcache": False},
    }
    ctx = build_context(details)

    firefox = next(c for c in ctx["component_timeline"] if c["basename"] == "firefox.exe")
    assert firefox["amcache_first_seen"] is None
    assert firefox["userassist_last_run"].isoformat() == "2026-07-14T14:15:22+00:00"
    assert firefox["bam_last_run"].isoformat() == "2026-07-14T14:15:30+00:00"
    assert firefox["last_activity"]["timestamp"].isoformat() == "2026-07-14T14:15:30+00:00"
    assert firefox["last_activity"]["source"] == "BAM"
    # MUICache still counts as an execution-adjacent source (Fix 6's decision) even
    # though its own timestamp is never used for timing.
    assert "MUICache" in firefox["seen_in"]
    assert "MUICache" in firefox["execution_sources"]


def test_component_timeline_excludes_context_category_findings():
    """Regression for a real bug: Phase 2 widened _PATH_RE so every device-evidence type
    (USBStor/USBDevices/MountedDevices/MountPoints2/PortableDevices) also gets a `path`
    field extracted, and _build_component_timeline() used to iterate every artifact_type
    unconditionally -- so every USB device, drive letter, and volume GUID on the machine
    was being counted as a "Tor Browser component" (a real acquisition showed "58
    distinct files" where only 8 were genuinely Tor-related). Every context-category
    finding here has a perfectly path-shaped description and would have polluted the old
    code; none of them may appear in component_timeline now."""
    details = {
        "summary": "x",
        "errors": [],
        "findings_by_type": {
            "UserAssist": [
                {
                    "description": "UserAssist evidence for 'E:\\Tor Browser\\firefox.exe' "
                    "(run_count=3).",
                    "source": "NTUSER.DAT",
                    "timestamp": "2026-07-14T14:15:22+00:00",
                    "category": "tor-direct",
                }
            ],
            "USBStor": [
                {
                    "description": "USBSTOR device 'Kingston DataTraveler' (manufacturer="
                    "Kingston, serial=ABC123, first_connected=unknown, "
                    "last_connected=unknown) — USB mass-storage connection history.",
                    "source": "SYSTEM",
                    "timestamp": None,
                    "category": "context",
                }
            ],
            "MountedDevices": [
                {
                    "description": "MountedDevices entry 'C:' (mount_type=drive_letter, "
                    "decoded=dynamic_disk_identifier, volume_guid=none).",
                    "source": "SYSTEM",
                    "timestamp": None,
                    "category": "context",
                }
            ],
            "MountPoints2": [
                {
                    "description": "MountPoints2 entry '{003b5b55-868f-11f0-a94a-"
                    "bc035877ab90}' — volume mounted by this user's session.",
                    "source": "NTUSER.DAT",
                    "timestamp": None,
                    "category": "context",
                }
            ],
            "PortableDevices": [
                {
                    "description": "Windows Portable Devices entry 'KINGSTON' "
                    "(device_id=_??_USBSTOR#...#ABC123#{guid}) — MTP/portable device "
                    "history.",
                    "source": "SYSTEM",
                    "timestamp": None,
                    "category": "context",
                }
            ],
        },
        "hives_provided": {"ntuser": True, "system": True, "amcache": False},
    }
    ctx = build_context(details)

    basenames = {c["basename"] for c in ctx["component_timeline"]}
    assert basenames == {"firefox.exe"}
    assert len(ctx["component_timeline"]) == 1
    # "N distinct files" in the template is literally this length -- proven correct by
    # construction, not a separately-maintained counter.


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


def _device_correlation_details(mounted_devices=None, usbstor=None, extra_findings=None):
    findings_by_type = {
        "UserAssist": [
            {
                "description": "UserAssist evidence for 'E:\\Tor Browser\\Tor Browser.lnk' "
                "(run_count=3).",
                "source": "NTUSER.DAT",
                "timestamp": "2026-07-14T14:15:22+00:00",
                "confidence": "high",
            }
        ],
    }
    if mounted_devices is not None:
        findings_by_type["MountedDevices"] = mounted_devices
    if usbstor is not None:
        findings_by_type["USBStor"] = usbstor
    if extra_findings:
        findings_by_type.update(extra_findings)
    return {
        "summary": "x",
        "errors": [],
        "findings_by_type": findings_by_type,
        "hives_provided": {"ntuser": True, "system": True, "amcache": False},
    }


def _mounted_devices_finding(mount_point, decoded, volume_guid="none"):
    return {
        "description": f"MountedDevices entry '{mount_point}' (mount_type=drive_letter, "
        f"decoded={decoded}, volume_guid={volume_guid}).",
        "source": "SYSTEM",
        "timestamp": None,
        "confidence": "high",
    }


def _usbstor_finding(
    name, manufacturer, serial, first_connected="unknown", last_connected="unknown"
):
    return {
        "description": f"USBSTOR device '{name}' (manufacturer={manufacturer}, serial={serial}, "
        f"first_connected={first_connected}, last_connected={last_connected}) "
        "— USB mass-storage connection history.",
        "source": "SYSTEM",
        "timestamp": "2026-06-01T00:00:00+00:00",
        "confidence": "high",
    }


def test_device_correlation_matches_drive_letter_to_usbstor_via_shared_serial():
    """The core Phase 2 capability: the Tor install's own drive letter (E:, from the
    UserAssist .lnk path) is mapped directly to a physical USB device by decoding
    MountedDevices' binary value and joining its embedded serial number against
    USBSTOR's independently-recorded serial_number -- a real structural correlation
    across two independent OS subsystems, not a coincidental path-suffix guess."""
    details = _device_correlation_details(
        mounted_devices=[
            _mounted_devices_finding(
                "E:",
                "_??_USBSTOR#Disk&Ven_SanDisk&Prod_Cruzer_Blade&Rev_1.00"
                "#4C53000012345678&0#{53f5630d-b6bf-11d0-94f2-00a0c91efb8b}",
            )
        ],
        usbstor=[
            _usbstor_finding(
                "Cruzer_Blade",
                "SanDisk",
                "4C53000012345678&0",
                first_connected="2026-05-01T00:00:00+00:00",
                last_connected="2026-06-01T00:00:00+00:00",
            ),
            _usbstor_finding("Unrelated Drive", "Kingston", "AAAA111"),
        ],
    )
    ctx = build_context(details)

    devices = ctx["devices"]
    assert devices["install_drive_letter"] == "E"
    assert devices["device_match"] == {
        "drive_letter": "E",
        "name": "Cruzer_Blade",
        "serial": "4C53000012345678&0",
        "first_connected": "2026-05-01T00:00:00+00:00",
        "last_connected": "2026-06-01T00:00:00+00:00",
        "dynamic_disk": False,
        "candidates": [],
    }

    matched_row = next(r for r in devices["usbstor"] if r["serial_number"] == "4C53000012345678&0")
    assert matched_row["is_relevant"] is True
    unrelated_row = next(r for r in devices["usbstor"] if r["serial_number"] == "AAAA111")
    assert unrelated_row["is_relevant"] is False

    # The plain-English install-location sentence names the specific device instead of
    # the generic "may be a USB drive" hedge (narrative.describe_install_location()).
    timeline_text = " ".join(ctx["narrative"]["timeline"])
    assert "Cruzer_Blade" in timeline_text
    assert "may be a USB drive" not in timeline_text


def test_device_correlation_dynamic_disk_replaces_generic_hedge_and_suppresses_candidates():
    """Windows does not support dynamic disks on removable USB media -- finding a
    "DMIO:ID:"-decoded MountedDevices value for the install drive is itself strong
    (not certain) evidence it's a fixed/internal-disk partition, not a USB stick. In this
    case no USBSTOR/PortableDevices candidates should ever be offered -- listing them
    would actively mislead, since we have a positive reason to believe it's NOT a USB
    device at all."""
    details = _device_correlation_details(
        mounted_devices=[_mounted_devices_finding("E:", "dynamic_disk_identifier")],
        usbstor=[_usbstor_finding("Cruzer_Blade", "SanDisk", "4C53000012345678&0")],
    )
    ctx = build_context(details)

    devices = ctx["devices"]
    assert devices["device_match"]["dynamic_disk"] is True
    assert devices["device_match"]["name"] is None
    assert devices["device_match"]["candidates"] == []

    timeline_text = " ".join(ctx["narrative"]["timeline"])
    assert "dynamic disk" in timeline_text
    assert "may be a USB drive" not in timeline_text

    device_story_text = " ".join(ctx["narrative"]["device_story"])
    assert "dynamic disk" in device_story_text
    assert "Cruzer_Blade" not in device_story_text


def test_device_correlation_volume_guid_hop_matches_sibling_mounted_devices_entry():
    """When the drive-letter's own decode yields a bare \\??\\Volume{GUID} rather than a
    USBSTOR path directly, a sibling MountedDevices entry literally named that same
    \\??\\Volume{GUID} string may carry the real USBSTOR-shaped decode -- an exact
    value-name hop, not a guess."""
    details = _device_correlation_details(
        mounted_devices=[
            _mounted_devices_finding(
                "E:", "not decoded", volume_guid="{53f5630d-b6bf-11d0-94f2-00a0c91efb8b}"
            ),
            {
                "description": "MountedDevices entry "
                "'\\??\\Volume{53f5630d-b6bf-11d0-94f2-00a0c91efb8b}' "
                "(mount_type=volume, decoded=_??_USBSTOR#Disk&Ven_SanDisk&Prod_Cruzer_Blade"
                "&Rev_1.00#4C53000012345678&0#{53f5630d-b6bf-11d0-94f2-00a0c91efb8b}, "
                "volume_guid=none).",
                "source": "SYSTEM",
                "timestamp": None,
                "confidence": "high",
            },
        ],
        usbstor=[_usbstor_finding("Cruzer_Blade", "SanDisk", "4C53000012345678&0")],
    )
    ctx = build_context(details)

    devices = ctx["devices"]
    assert devices["device_match"]["name"] == "Cruzer_Blade"
    assert devices["device_match"]["serial"] == "4C53000012345678&0"


def test_device_correlation_portable_devices_only_match():
    """A USB mass-storage device enumerated via WPD (Windows Portable Devices) embeds the
    same USBSTOR-shaped serial in its own subkey name -- confirmed against real evidence.
    When no USBSTOR entry shares that serial but a PortableDevices entry does, the WPD
    entry is still a valid match (Fix for a Phase 2 bug that put PortableDevices in the
    "never matches" bucket)."""
    details = _device_correlation_details(
        mounted_devices=[
            _mounted_devices_finding(
                "E:",
                "_??_USBSTOR#Disk&Ven_Kingston&Prod_DataTraveler_3.0&Rev_PMAP"
                "#E0D55E6CBD0FE99129B50047&0#{53f56307-b6bf-11d0-94f2-00a0c91efb8b}",
            )
        ],
        extra_findings={
            "PortableDevices": [
                {
                    "description": "Windows Portable Devices entry 'KINGSTON' "
                    "(device_id=_??_USBSTOR#Disk&Ven_Kingston&Prod_DataTraveler_3.0&Rev_PMAP"
                    "#E0D55E6CBD0FE99129B50047&0#{53f56307-b6bf-11d0-94f2-00a0c91efb8b}) "
                    "— MTP/portable device history.",
                    "source": "SYSTEM",
                    "timestamp": "2026-09-15T10:30:09+00:00",
                    "confidence": "low",
                }
            ]
        },
    )
    ctx = build_context(details)

    devices = ctx["devices"]
    assert devices["device_match"]["name"] == "KINGSTON"
    # PortableDevices carries no serial_number/first_connected/last_connected fields.
    assert devices["device_match"]["serial"] is None
    portable_row = devices["portable_devices"][0]
    assert portable_row["is_relevant"] is True


def test_device_correlation_no_mounted_devices_entry_leaves_everything_unflagged():
    details = _device_correlation_details(
        usbstor=[_usbstor_finding("Cruzer_Blade", "SanDisk", "4C53000012345678&0")],
    )
    ctx = build_context(details)

    devices = ctx["devices"]
    assert devices["install_drive_letter"] == "E"
    assert devices["device_match"]["name"] is None
    assert devices["device_match"]["dynamic_disk"] is False
    assert all(not row["is_relevant"] for row in devices["usbstor"])

    # Falls back to exactly the pre-Phase-2 generic wording.
    timeline_text = " ".join(ctx["narrative"]["timeline"])
    assert "may be a USB drive" in timeline_text


def test_device_correlation_unknown_lists_usbstor_and_portable_candidates_never_usbdevices():
    """No MountedDevices/direct correlation at all -- the "could not be identified"
    sentence must list every USBStor/PortableDevices entry as a possible candidate, and
    must never offer a generic USBDevices entry (e.g. a USB hub/camera/sensor) as one."""
    details = _device_correlation_details(
        usbstor=[_usbstor_finding("Cruzer_Blade", "SanDisk", "4C53000012345678&0")],
        extra_findings={
            "PortableDevices": [
                {
                    "description": "Windows Portable Devices entry 'KINGSTON' "
                    "(device_id=_??_USBSTOR#...#E0D5...&0#{guid}) — MTP/portable device "
                    "history.",
                    "source": "SYSTEM",
                    "timestamp": None,
                    "confidence": "low",
                }
            ],
            "USBDevices": [
                {
                    "description": "USB device 'USB Root Hub (USB 3.0)' (vid=unknown, "
                    "pid=unknown) enumerated by Windows.",
                    "source": "SYSTEM",
                    "timestamp": None,
                    "confidence": "medium",
                }
            ],
        },
    )
    ctx = build_context(details)

    devices = ctx["devices"]
    candidate_names = {c["name"] for c in devices["device_match"]["candidates"]}
    assert candidate_names == {"Cruzer_Blade", "KINGSTON"}
    assert "USB Root Hub (USB 3.0)" not in candidate_names

    device_story_text = " ".join(ctx["narrative"]["device_story"])
    assert "could not be identified" in device_story_text
    assert "Cruzer_Blade" in device_story_text
    assert "KINGSTON" in device_story_text
    assert "USB Root Hub" not in device_story_text


def test_device_correlation_flags_mountpoints2_and_emdmgmt_sharing_the_matched_serial():
    details = _device_correlation_details(
        mounted_devices=[
            _mounted_devices_finding(
                "E:",
                "_??_USBSTOR#Disk&Ven_SanDisk&Prod_Cruzer_Blade&Rev_1.00"
                "#4C53000012345678&0#{53f5630d-b6bf-11d0-94f2-00a0c91efb8b}",
            )
        ],
        usbstor=[_usbstor_finding("Cruzer_Blade", "SanDisk", "4C53000012345678&0")],
        extra_findings={
            "MountPoints2": [
                {
                    "description": "MountPoints2 entry "
                    "'_??_USBSTOR#Disk&Ven_SanDisk&Prod_Cruzer_Blade&Rev_1.00"
                    "#4C53000012345678&0#{53f5630d-b6bf-11d0-94f2-00a0c91efb8b}' — "
                    "volume mounted by this user's session.",
                    "source": "NTUSER.DAT",
                    "timestamp": None,
                    "confidence": "low",
                },
                {
                    "description": "MountPoints2 entry '{unrelated-guid}' — volume mounted "
                    "by this user's session.",
                    "source": "NTUSER.DAT",
                    "timestamp": None,
                    "confidence": "low",
                },
            ],
            "EMDMgmt": [
                {
                    "description": "EMDMgmt entry "
                    "'SanDisk_Cruzer_Blade&4C53000012345678&0' "
                    "(device_capacity=8192) — ReadyBoost device-eligibility test record.",
                    "source": "SOFTWARE",
                    "timestamp": None,
                    "confidence": "medium",
                }
            ],
        },
    )
    ctx = build_context(details)

    devices = ctx["devices"]
    mountpoints2_relevant = [r for r in devices["mountpoints2"] if r["is_relevant"]]
    mountpoints2_other = [r for r in devices["mountpoints2"] if not r["is_relevant"]]
    assert len(mountpoints2_relevant) == 1
    assert "4C53000012345678" in mountpoints2_relevant[0]["path"]
    assert len(mountpoints2_other) == 1

    assert all(row["is_relevant"] for row in devices["emdmgmt"])
