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
