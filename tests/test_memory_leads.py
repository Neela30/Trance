"""No target on a full-memory image: onion sites with activity are reported as leads, not
findings (modules/module_c_memory/analyzer._build_leads), and the report and app say so."""

from pathlib import Path

import main
from core.config import TranceConfig
from gui.history import case_leads
from modules.module_c_memory.analyzer import analyze

SITE = "izzawro6enzkhyunavp5on7zozrq56unspben3vi2sbxtxqyfoh5obyd.onion"
TOR_OWN = "2gzyxa5ihm7nsggfxnu52rck2vv4rvmdlkiu3zzui5du4xyclen53wid.onion"  # torproject.org
RANSOM = "hiveapi5qsnctp7rkmgrd3nrk64o5u6vdbc2ua4aevl2r6yc3j7kd4yd.onion"  # in AV signatures
CUT = "yunavp5on7zozrq56unspben3vi2sbxtxqyfoh5obyd.onion"  # SITE cut by string extraction
DETECTION = "wtyafjyhwqrgo4a45wdvvwhen3cx4euie73qvlhkhvlrexljoyuklaad.onion"  # AV detection name


def _image(tmp_path: Path) -> Path:
    strings = [
        f"http://{SITE}/library/book1",
        f"http://{SITE}/search",
        f"http://{SITE}/static/style.css",
        f"http://{SITE}/login user=tessa.maricourt",
        (
            '<title>Harbour Library</title> <a href="/library/book1"> <a href="/search">'
            ' <a href="/static/style.css">'
        ),
        f"http://{TOR_OWN}/download/",
        f"http://{RANSOM}/",
        f"http://{CUT}/library/x",
        f"http://{DETECTION}/btRansom:Linux/Filecoder.V!MTB",
    ]
    image = tmp_path / "fullmem_20261009T154539Z.raw"
    image.write_bytes(b"\x00".join(s.encode() for s in strings) + b"\x00")
    return image


def test_no_target_reports_the_visited_site_as_a_lead_and_nothing_as_a_finding(tmp_path):
    report = analyze(_image(tmp_path), None, None, None, source_type="full-memory")

    assert report["artifacts"] == []
    assert report["targeted"]["urls"] == [] and report["key_findings"]["credentials"] == []
    # Tor Browser's own site, bare or single addresses from antivirus signature data and a
    # cut-off copy of the real address are not leads; the site actually used is.
    (lead,) = report["leads"]["sites"]
    assert lead["onion"] == SITE
    assert {"/library/book1", "/search", "/login"} <= set(lead["pages"])
    assert lead["usernames"] == ["tessa.maricourt"]
    assert lead["page_titles"] == ["Harbour Library"]
    assert report["leads"]["lead_count"] == lead["page_count"] + 1 + 1
    assert all(s["onion"] != TOR_OWN for s in report["targeting_suggestions"])


def test_a_named_target_gets_findings_and_no_leads(tmp_path):
    report = analyze(_image(tmp_path), SITE, None, None, source_type="full-memory")

    assert "leads" not in report
    assert any(a["artifact_type"] == "url" for a in report["artifacts"])
    assert all("anchor_host" not in c for c in report["targeted"]["credentials"])


def test_report_and_app_offer_the_lead_without_calling_it_a_finding(tmp_path):
    kwargs = {
        "module_a_registry": {},
        "module_b_disk": {},
        "module_c_memory": {"dump": _image(tmp_path), "source_type": "full-memory"},
    }
    result = main.run_pipeline(TranceConfig("case", tmp_path / "out"), kwargs)
    html = result.report_path.read_text(encoding="utf-8")

    assert "no target given · 1 onion site with activity" in html
    assert "0 findings" not in html
    assert "Leads: onion sites with activity in memory" in html
    assert SITE in html and RANSOM not in html.split("Leads: onion sites")[1].split("</section>")[0]

    leads = case_leads(result.report_path)
    assert leads.onions == [SITE] and leads.case_name == "case"
