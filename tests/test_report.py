from core.config import TranceConfig
from findings import build_findings
from report import write_report


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
