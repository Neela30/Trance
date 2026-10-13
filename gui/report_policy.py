"""What the Report tab's web view may load, as Qt-free logic (unit-tested without PySide6).

report.html is built from evidence taken off a possibly compromised machine. It is escaped
and carries a strict Content-Security-Policy, and the view also runs with JavaScript off and
no access from the local file to the network. This is the last layer: the view may only
ever show the one report it was asked to show -- in-page #anchors included -- and never
navigates anywhere else (a web page, another local file, a javascript:/data: URL).
"""

from __future__ import annotations

from pathlib import Path
from urllib.parse import unquote, urlsplit
from urllib.request import url2pathname

# QWebEngineSettings.WebAttribute names and the value the report view needs. Kept here
# (as names) so the policy is reviewable and testable without Qt installed.
WEB_ATTRIBUTES = {
    "JavascriptEnabled": False,  # the report has no script; CSP also forbids it
    "JavascriptCanOpenWindows": False,
    "JavascriptCanAccessClipboard": False,
    "LocalContentCanAccessRemoteUrls": False,  # file:// page may not reach the network
    "LocalContentCanAccessFileUrls": False,  # ... nor read other local files
    "AllowRunningInsecureContent": False,
    "PluginsEnabled": False,
    "PdfViewerEnabled": False,
    "AutoLoadIconsForPage": False,
    "DnsPrefetchEnabled": False,
    "NavigateOnDropEnabled": False,
    "WebGLEnabled": False,
    "ScreenCaptureEnabled": False,
}


def _local_path(url: str) -> Path | None:
    parts = urlsplit(url)
    if parts.scheme.lower() != "file":
        return None
    path = unquote(parts.path)
    if parts.netloc and parts.netloc.lower() != "localhost":
        return None  # file://server/share -- a network location, never the report
    try:
        return Path(url2pathname(path)).resolve()
    except (OSError, ValueError):
        return None


def navigation_allowed(url: str, report_path: Path | None) -> bool:
    """True only for the report file itself (any #fragment) and about:blank."""
    if url in ("about:blank", ""):
        return True
    if report_path is None:
        return False
    local = _local_path(url)
    if local is None:
        return False
    try:
        return local == Path(report_path).resolve()
    except OSError:
        return False
