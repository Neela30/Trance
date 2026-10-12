import json

from core.hashing import hash_bytes
from gui.pdf_export import default_pdf_path, record_pdf_export


def test_default_pdf_path_is_named_after_the_case_next_to_the_report(tmp_path):
    report = tmp_path / "case7" / "report.html"
    assert default_pdf_path(report) == (tmp_path / "case7" / "case7_report.pdf").resolve()


def test_record_pdf_export_appends_to_custody_and_ties_pdf_to_report(tmp_path):
    report = tmp_path / "report.html"
    report.write_text("<html></html>")
    (tmp_path / "custody.json").write_text(json.dumps([{"action": "generated"}]))
    pdf = tmp_path / "case_report.pdf"
    pdf.write_bytes(b"%PDF-1.4 test")

    digest = record_pdf_export(report, pdf)

    assert digest == hash_bytes(b"%PDF-1.4 test")
    entries = json.loads((tmp_path / "custody.json").read_text())
    assert entries[0] == {"action": "generated"}
    assert entries[-1]["action"] == "exported_pdf"
    assert entries[-1]["sha256"] == digest
    assert hash_bytes(b"<html></html>") in entries[-1]["notes"]


def test_record_pdf_export_starts_custody_when_missing(tmp_path):
    report = tmp_path / "report.html"
    report.write_text("x")
    pdf = tmp_path / "r.pdf"
    pdf.write_bytes(b"%PDF")
    record_pdf_export(report, pdf)
    assert len(json.loads((tmp_path / "custody.json").read_text())) == 1
