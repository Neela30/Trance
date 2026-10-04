from datetime import datetime, timezone

from core.config import TranceConfig
from findings import build_findings
from report import _format_timestamp, write_report


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
