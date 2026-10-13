"""Evidence comes off a possibly compromised machine: anything in it (a file name, a registry
value, a URL in memory) can be attacker-chosen. These tests feed script tags, event-handler
attributes and javascript: URLs through every route into the report and assert none of it
comes out as live markup -- and that the report's CSP would block it if it ever did."""

from __future__ import annotations

import re
from html.parser import HTMLParser
from pathlib import Path

from core.config import TranceConfig
from core.schema import Artifact, ModuleResult
from findings import build_findings
from report import render_report

PAYLOADS = (
    "<script>alert('xss')</script>",
    '"><img src=x onerror="alert(1)">',
    "<svg onload=alert(1)>",
    "javascript:alert(document.cookie)",
    '<a href="javascript:alert(1)">click</a>',
    "</td></tr></table><iframe src=//evil.example></iframe>",
    "' onmouseover='alert(1)",
)
PAYLOAD = " | ".join(PAYLOADS)
DANGEROUS_TAGS = {"script", "iframe", "object", "embed", "frame", "base", "form", "svg", "img"}


class _Collector(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.tags: list[tuple[str, list[tuple[str, str | None]]]] = []

    def handle_starttag(self, tag, attrs):
        self.tags.append((tag, attrs))

    handle_startendtag = handle_starttag


def _parse(html: str) -> list[tuple[str, list[tuple[str, str | None]]]]:
    collector = _Collector()
    collector.feed(html)
    return collector.tags


def _assert_inert(html: str) -> None:
    tags = _parse(html)
    names = {tag for tag, _ in tags}
    assert not names & DANGEROUS_TAGS, names & DANGEROUS_TAGS
    for tag, attrs in tags:
        for name, value in attrs:
            assert not name.lower().startswith("on"), (tag, name, value)
            if name.lower() in ("href", "src", "action", "formaction", "xlink:href"):
                assert not (value or "").strip().lower().startswith(("javascript:", "data:")), (
                    tag,
                    name,
                    value,
                )
    # The raw payload text never appears unescaped anywhere in the document.
    for raw in ("<script>", "<img src=x", "<svg onload", "<iframe", '<a href="javascript:'):
        assert raw not in html


def _module_a_with_payloads() -> ModuleResult:
    finding = {
        "description": f"UserAssist evidence for 'E:\\Tor Browser\\{PAYLOAD}\\firefox.exe' (run_count=1).",
        "source": f"NTUSER.DAT {PAYLOAD}",
        "timestamp": "2026-09-03T04:41:53+00:00",
        "confidence": "high",
    }
    return ModuleResult(
        module="module_a_registry",
        status="partial",
        artifacts=[
            Artifact(
                module="module_a_registry",
                artifact_type="UserAssist",
                source=PAYLOAD,
                description=PAYLOAD,
            )
        ],
        details={
            "summary": PAYLOAD,
            "errors": [PAYLOAD],
            "warnings": [
                {
                    "artifact_type": PAYLOAD,
                    "source": PAYLOAD,
                    "reason": PAYLOAD,
                    "traceback": PAYLOAD,
                }
            ],
            "findings_by_type": {"UserAssist": [finding]},
            "hives_provided": {"ntuser": True, "system": False, "amcache": False},
        },
    )


def _generic_with_payloads(name: str) -> ModuleResult:
    """status=error routes a module through the generic artifact table."""
    return ModuleResult(
        module=name,
        status="error",
        message=PAYLOAD,
        artifacts=[
            Artifact(
                module=name,
                artifact_type=PAYLOAD,
                source=PAYLOAD,
                description=PAYLOAD,
                sha256=PAYLOAD,
                timestamp=PAYLOAD,
            )
        ],
        details={"warnings": [{"artifact_type": PAYLOAD, "source": PAYLOAD, "reason": PAYLOAD}]},
    )


def _render(tmp_path: Path, integrity: dict | None = None) -> str:
    config = TranceConfig(
        case_name=PAYLOAD,
        output_dir=tmp_path / PAYLOAD,
        evidence_dir=Path(PAYLOAD),
    )
    results = [
        _module_a_with_payloads(),
        _generic_with_payloads("module_b_disk"),
        _generic_with_payloads("module_c_memory"),
    ]
    return render_report(build_findings(config, results, integrity=integrity), "UTC")


def test_evidence_payloads_render_escaped_and_inert(tmp_path):
    html = _render(tmp_path)

    _assert_inert(html)
    # Escaped, not dropped: the examiner still sees exactly what the evidence said.
    assert "&lt;script&gt;alert(" in html
    assert "onerror=" in html  # as text inside an escaped string, not as an attribute
    assert "javascript:alert(document.cookie)" in html


def test_integrity_failure_section_escapes_file_names(tmp_path):
    integrity = {
        "status": "failed",
        "message": PAYLOAD,
        "mismatched": [{"path": PAYLOAD, "record": PAYLOAD, "recorded": "a", "actual": "b"}],
        "missing": [],
        "invalid": [{"record": PAYLOAD, "reason": PAYLOAD}],
        "unhashed": [],
        "verified": [],
        "checked": 1,
    }
    html = _render(tmp_path, integrity)

    _assert_inert(html)
    assert "Evidence integrity check failed" in html


def test_title_is_escaped(tmp_path):
    html = _render(tmp_path)
    title = re.search(r"<title>(.*?)</title>", html, re.DOTALL).group(1)
    assert "<script>" not in title
    assert "&lt;script&gt;" in title


def test_report_has_a_strict_content_security_policy_before_any_evidence_text(tmp_path):
    html = _render(tmp_path)
    tags = _parse(html)
    metas = [dict(attrs) for tag, attrs in tags if tag == "meta"]
    csp = next(m["content"] for m in metas if m.get("http-equiv") == "Content-Security-Policy")
    directives = {d.split()[0]: d.split()[1:] for d in csp.split(";") if d.strip()}

    assert directives["default-src"] == ["'none'"]
    assert directives["script-src"] == ["'none'"]
    assert directives["object-src"] == ["'none'"]
    assert directives["base-uri"] == ["'none'"]
    assert directives["form-action"] == ["'none'"]
    assert directives["connect-src"] == ["'none'"]
    # The only thing allowed is the report's own inline CSS (and data: images).
    assert directives["style-src"] == ["'unsafe-inline'"]
    # Before <title>, the first evidence-derived text in the document.
    assert html.index("Content-Security-Policy") < html.index("<title>")


def test_report_template_has_no_script_and_no_safe_filter():
    """The CSP forbids script, so the template must not need any; and nothing in the
    templates may switch autoescaping off for a value."""
    root = Path(__file__).resolve().parents[1]
    for template in (
        root / "report_template.html.j2",
        root / "modules" / "module_c_memory" / "report_template.html.j2",
    ):
        text = template.read_text(encoding="utf-8")
        assert "<script" not in text.lower()
        assert "|safe" not in text.replace(" ", "")
        assert "autoescape false" not in text.replace("  ", " ")
        assert "Content-Security-Policy" in text
