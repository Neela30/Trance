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
            "RecentDocs": [{"description": "d1", "source": "NTUSER.DAT", "timestamp": None}],
            "ShimCache": [{"description": "d2", "source": "SYSTEM", "timestamp": None}],
            "UserAssist": [{"description": "d3", "source": "NTUSER.DAT", "timestamp": "t"}],
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


def test_component_timeline_empty_when_no_paths_extractable():
    details = {
        "summary": "x",
        "errors": [],
        "findings_by_type": {"RecentDocs": [{"description": "no quoted path here", "source": "NTUSER.DAT", "timestamp": None}]},
        "hives_provided": {"ntuser": True, "system": False, "amcache": False},
    }
    ctx = build_context(details)
    assert ctx["component_timeline"] == []
    assert ctx["corroborated_components"] == 0
