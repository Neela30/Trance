"""Saving a case report as PDF -- the Qt-free half (file naming, custody record).

The PDF is what goes to court; report.html and findings.json stay as the electronic
exhibits. Every export is hashed and appended to the case's custody.json, so the PDF on
file can be shown to be the one TRANCE produced from that report.
"""

from __future__ import annotations

import json
from dataclasses import asdict
from pathlib import Path

from core.custody_log import CustodyEntry
from core.hashing import hash_file

CUSTODY_FILENAME = "custody.json"

# Run in the page before printing so collapsed <details> print open (the report's print
# CSS does the same for a browser's Ctrl+P).
OPEN_ALL_DETAILS_JS = """
document.querySelectorAll("details:not([open])").forEach(function (d) {
  d.setAttribute("data-print-opened", "");
  d.open = true;
});
"""
RESTORE_DETAILS_JS = """
document.querySelectorAll("details[data-print-opened]").forEach(function (d) {
  d.removeAttribute("data-print-opened");
  d.open = false;
});
"""


def default_pdf_path(report_path: Path) -> Path:
    """<case dir>/<case>_<page>.pdf next to the page: <case>_report.pdf for report.html,
    <case>_exhibit_list.pdf for exhibit_list.html."""
    page = Path(report_path).resolve()
    return page.parent / f"{page.parent.name}_{page.stem}.pdf"


def record_pdf_export(report_path: Path, pdf_path: Path) -> str:
    """Hash the saved PDF and append it to the case's custody.json; returns the hash.

    The entry names report.html's own hash too, so the PDF is tied to the exact report it
    was printed from. A case folder without custody.json gets one started.
    """
    report_path = Path(report_path).resolve()
    pdf_path = Path(pdf_path).resolve()
    pdf_sha256 = hash_file(pdf_path)
    custody_path = report_path.parent / CUSTODY_FILENAME
    entries = json.loads(custody_path.read_text()) if custody_path.is_file() else []
    entries.append(
        asdict(
            CustodyEntry(
                artifact_path=str(pdf_path),
                sha256=pdf_sha256,
                action="exported_pdf",
                notes=f"printed from {report_path.name} sha256={hash_file(report_path)}",
            )
        )
    )
    custody_path.write_text(json.dumps(entries, indent=2))
    return pdf_sha256
