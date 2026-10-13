from pathlib import Path

import pytest

from gui.report_policy import WEB_ATTRIBUTES, navigation_allowed


@pytest.fixture
def report(tmp_path):
    path = tmp_path / "case" / "report.html"
    path.parent.mkdir()
    path.write_text("<html></html>")
    return path


def test_the_report_itself_and_its_anchors_are_allowed(report):
    url = report.resolve().as_uri()
    assert navigation_allowed(url, report)
    assert navigation_allowed(url + "#appendix-profiles", report)
    assert navigation_allowed("about:blank", report)


@pytest.mark.parametrize(
    "url",
    [
        "https://evil.example/collect?d=1",
        "http://127.0.0.1:5000/",
        "javascript:alert(1)",
        "data:text/html,<script>alert(1)</script>",
        "ftp://evil.example/x",
        "file://evil-server/share/report.html",
        "blob:null/123",
    ],
)
def test_everything_else_is_refused(report, url):
    assert not navigation_allowed(url, report)


def test_other_local_files_are_refused(report, tmp_path):
    other = tmp_path / "secret.txt"
    other.write_text("x")
    assert not navigation_allowed(other.resolve().as_uri(), report)
    assert not navigation_allowed(Path(report.parent / "findings.json").resolve().as_uri(), report)


def test_nothing_is_allowed_before_a_report_is_loaded(report):
    assert not navigation_allowed(report.resolve().as_uri(), None)


def test_view_runs_without_javascript_or_remote_access():
    assert WEB_ATTRIBUTES["JavascriptEnabled"] is False
    assert WEB_ATTRIBUTES["LocalContentCanAccessRemoteUrls"] is False
    assert WEB_ATTRIBUTES["LocalContentCanAccessFileUrls"] is False
    assert WEB_ATTRIBUTES["PluginsEnabled"] is False
    assert not any(WEB_ATTRIBUTES.values())
