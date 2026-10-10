from datetime import datetime, timezone
from pathlib import Path

from core.config import TranceConfig
from core.schema import ModuleResult
from findings import build_findings
from report import _format_timestamp, _resolve_local_tz, _wrap_path, render_report, write_report


class TestFormatTimestamp:
    def test_none_and_empty_become_dash(self):
        assert _format_timestamp(None) == "—"
        assert _format_timestamp("") == "—"

    def test_iso_string_with_microseconds_and_offset_is_simplified(self):
        assert _format_timestamp("2026-09-03T04:41:53.211000+00:00") == "2026-09-03 04:41:53 UTC"

    def test_datetime_object_formats_the_same_way_as_an_equivalent_string(self):
        dt = datetime(2026, 9, 3, 4, 41, 53, tzinfo=timezone.utc)
        assert _format_timestamp(dt) == "2026-09-03 04:41:53 UTC"

    def test_unparseable_string_is_returned_unchanged_rather_than_hidden(self):
        assert _format_timestamp("not-a-timestamp") == "not-a-timestamp"


class TestWrapPath:
    def test_inserts_wbr_after_every_backslash(self):
        result = _wrap_path(r"C:\Users\Admin\Downloads\x.exe")
        assert result == r"C:\<wbr>Users\<wbr>Admin\<wbr>Downloads\<wbr>x.exe"

    def test_inserts_wbr_after_forward_slashes_too(self):
        result = _wrap_path("a/b/c.txt")
        assert result == "a/<wbr>b/<wbr>c.txt"

    def test_escapes_html_special_characters(self):
        # Never breaks mid-word (no bare "anywhere" break), but still must not let a
        # path smuggle markup into the page.
        result = _wrap_path(r"C:\<script>\x.exe")
        assert "<script>" not in result
        assert "&lt;script&gt;" in result

    def test_none_and_empty_become_a_dash(self):
        assert _wrap_path(None) == "—"
        assert _wrap_path("") == "—"

    def test_result_is_marked_safe_for_the_template(self):
        from markupsafe import Markup

        assert isinstance(_wrap_path(r"C:\x.exe"), Markup)


class TestResolveLocalTz:
    def test_explicit_value_passes_through_unchanged(self):
        assert _resolve_local_tz("Asia/Colombo") == "Asia/Colombo"

    def test_none_resolves_to_something_or_none_but_never_raises(self):
        # tzlocal is installed in this project's deps; on a machine without it (or
        # without usable tzdata) this must degrade to None, never raise.
        result = _resolve_local_tz(None)
        assert result is None or isinstance(result, str)


def test_tzdata_package_provides_a_real_zone_database():
    # Windows has no OS-level tz database, so zoneinfo.ZoneInfo depends entirely on the
    # `tzdata` PyPI package (requirements.txt) to resolve any zone name at all -- both
    # --report-timezone (CLI and GUI) and auto-detected local time rely on it. If tzdata
    # were missing, or a PyInstaller build failed to bundle its data files (see
    # requirements.txt / README.md's trance-analyze and trance-gui build commands), every
    # zone name would silently fail to resolve (narrative.format_dual_time() et al. treat
    # a resolution failure the same as "no zone configured") instead of raising loudly --
    # this test is the one place that catches tzdata going fully missing.
    from zoneinfo import ZoneInfo

    zone = ZoneInfo("Asia/Colombo")
    assert zone is not None
    assert datetime(2026, 1, 1, tzinfo=timezone.utc).astimezone(zone).utcoffset() is not None


def _module_a_result_with_one_launch() -> ModuleResult:
    finding = {
        "description": (
            "UserAssist evidence for 'E:\\Tor Browser\\Browser\\firefox.exe' "
            "(run_count=1). Confidence: HIGH."
        ),
        "source": "NTUSER.DAT",
        "timestamp": "2026-09-03T04:41:53+00:00",
    }
    return ModuleResult(
        module="module_a_registry",
        status="ok",
        artifacts=[],
        details={
            "summary": "Tor Browser launched 1 time.",
            "errors": [],
            "findings_by_type": {"UserAssist": [finding]},
            "hives_provided": {"ntuser": True, "system": False, "amcache": False},
        },
    )


def test_render_report_includes_glossary_for_a_module_a_case(tmp_path):
    config = TranceConfig(case_name="case", output_dir=tmp_path)
    findings = build_findings(config, [_module_a_result_with_one_launch()])

    html = render_report(findings, local_tz="Asia/Colombo")

    assert "Glossary" in html
    assert "UserAssist" in html
    assert "NTUSER.DAT" in html


def test_render_report_narrative_uses_the_given_timezone(tmp_path):
    config = TranceConfig(case_name="case", output_dir=tmp_path)
    findings = build_findings(config, [_module_a_result_with_one_launch()])

    html = render_report(findings, local_tz="Asia/Colombo")

    assert "What happened" in html
    assert "10:11 AM Asia/Colombo" in html


def _module_a_result_partial_status() -> ModuleResult:
    """One real finding plus one failed extractor -- the exact shape a real "ShellBags
    crashed, everything else is fine" run now produces (see modules/module_a_registry/
    __init__.py's status computation and core.schema.ModuleResult's own docstring)."""
    finding = {
        "description": (
            "UserAssist evidence for 'E:\\Tor Browser\\Browser\\firefox.exe' (run_count=1)."
        ),
        "source": "NTUSER.DAT",
        "timestamp": "2026-09-03T04:41:53+00:00",
        "confidence": "high",
    }
    return ModuleResult(
        module="module_a_registry",
        status="partial",
        artifacts=[],
        details={
            "summary": "Tor Browser launched 1 time.",
            "errors": ["ShellBags (UsrClass.dat): invalid format string: %hhu."],
            "warnings": [
                {
                    "artifact_type": "ShellBags",
                    "source": "UsrClass.dat",
                    "reason": "invalid format string: %hhu.",
                    "traceback": "Traceback (most recent call last): ...",
                }
            ],
            "findings_by_type": {"UserAssist": [finding]},
            "hives_provided": {"ntuser": True, "system": False, "amcache": False},
        },
    )


def test_partial_status_module_still_gets_its_full_presenter(tmp_path):
    """The actual bug this status model fixes: a "partial" module (one extractor failed,
    others didn't) must still get its rich narrative/tables section -- previously the
    presenter gate only matched status == "ok", so this exact scenario silently fell
    back to a bare generic artifact table, discarding the real UserAssist finding's
    narrative/confidence presentation entirely."""
    config = TranceConfig(case_name="case", output_dir=tmp_path)
    findings = build_findings(config, [_module_a_result_partial_status()])

    html = render_report(findings, local_tz="Asia/Colombo")

    assert "What happened" in html  # rich presenter engaged, not the generic fallback
    assert "ShellBags" in html
    assert "parser error" in html  # the plain-English extraction-warning sentence


def test_error_status_module_falls_back_to_generic_table():
    config = TranceConfig(case_name="case", output_dir=Path("."))
    result = ModuleResult(
        module="module_a_registry",
        status="error",
        artifacts=[],
        details={"summary": "x", "errors": [], "findings_by_type": {}, "hives_provided": {}},
        message="Hash mismatch for NTUSER.DAT",
    )
    findings = build_findings(config, [result])

    html = render_report(findings)

    assert "What happened" not in html
    assert "Hash mismatch for NTUSER.DAT" in html


def test_write_report_handles_non_ascii_template_content(tmp_path):
    """report_template.html.j2 has literal non-ASCII characters (e.g. the arrow used
    for CSS bullets and timeline ranges) -- write_report must not rely on the
    platform's default text encoding. cp1252 (Windows' default) can't encode that
    arrow at all, which crashed every real report write on Windows until write_report
    started passing encoding="utf-8" explicitly."""
    config = TranceConfig(case_name="case", output_dir=tmp_path, evidence_dir=None)
    findings = build_findings(config, [])

    path = write_report(findings, tmp_path)

    html = path.read_text(encoding="utf-8")
    assert "→" in html


def _registry_and_memory(groups_rows, opened, last_running):
    from datetime import datetime

    from modules.module_c_memory.report import _process_activity

    registry = {
        "component_timeline": [
            {
                "basename": "firefox.exe",
                "userassist_last_run": datetime.fromisoformat(opened) if opened else None,
                "bam_last_run": datetime.fromisoformat(last_running) if last_running else None,
            }
        ]
    }
    memory = {
        "volatility3": {
            "process_activity": _process_activity(groups_rows, "fullmem_20261009T182529Z.raw")
        }
    }
    return registry, memory


def _ff(pid, ppid, created, exited=None):
    return {
        "ImageFileName": "firefox.exe",
        "PID": pid,
        "PPID": ppid,
        "CreateTime": created,
        "ExitTime": exited,
    }


def test_memory_shows_an_earlier_run_and_matches_bam_to_the_exit():
    from report import _relate_processes_to_registry

    rows = [
        _ff(5944, 632, "2026-10-09T18:02:13+00:00", "2026-10-09T18:05:49+00:00"),
        _ff(7160, 4828, "2026-10-09T18:06:12+00:00", "2026-10-09T18:15:59+00:00"),
    ]
    notes = _relate_processes_to_registry(
        *_registry_and_memory(rows, "2026-10-09T18:05:31+00:00", "2026-10-09T18:15:59.960830+00:00")
    )
    assert len(notes) == 2
    assert "18:02:13" in notes[0] and "18:05:31" in notes[0] and "18:05:49" in notes[0]
    assert "PID 7160" in notes[1] and "ended" in notes[1]


def test_no_notes_when_memory_agrees_with_the_registry():
    from report import _relate_processes_to_registry

    rows = [_ff(7160, 4828, "2026-10-09T18:05:40+00:00", "2026-10-09T18:15:59+00:00")]
    # Opened 18:05:31 (process 9 s later: same run); BAM far from any exit.
    notes = _relate_processes_to_registry(
        *_registry_and_memory(rows, "2026-10-09T18:05:31+00:00", "2026-10-09T17:00:00+00:00")
    )
    assert notes == []


def test_no_notes_without_both_modules():
    from report import _relate_processes_to_registry

    assert _relate_processes_to_registry(None, {"volatility3": {}}) == []
    assert _relate_processes_to_registry({"component_timeline": []}, None) == []
