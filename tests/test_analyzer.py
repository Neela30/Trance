from pathlib import Path

from modules.module_c_memory.analyzer import PROXIMITY_WINDOW, analyze


def make_dump(tmp_path: Path, data: bytes) -> Path:
    dump = tmp_path / "d.bin"
    dump.write_bytes(data)
    return dump


def test_credential_host_anchoring_applies_only_to_full_memory(tmp_path):
    # Real hit: "user=..." sits in the same string as the target host.
    real = b"http://target.onion/login user=alice password=hunter2\x00"
    # Unrelated hit: "user=..." from some other process, no mention of the target anywhere nearby.
    noise = b"installer_id user=SOMEUNRELATEDGUID1234\x00"
    dump = make_dump(tmp_path, real + noise)

    process_report = analyze(
        dump, onion="target.onion", host=None, username=None, source_type="process"
    )
    assert not process_report["host_anchoring"]["applied"]
    # process dumps are unfiltered by host-anchoring: all 3 field=value hits show up
    # (alice, hunter2, and the unrelated installer GUID).
    assert len(process_report["targeted"]["credentials"]) == 3

    full_report = analyze(
        dump, onion="target.onion", host=None, username=None, source_type="full-memory"
    )
    assert full_report["host_anchoring"]["applied"]
    fields_values = {(c["field"], c["value"]) for c in full_report["targeted"]["credentials"]}
    assert ("user", "alice") in fields_values
    assert not any(v == "SOMEUNRELATEDGUID1234" for _, v in fields_values)
    assert full_report["host_anchoring"]["unanchored"]["credentials"]["count"] == 1


def test_targeting_reports_the_given_host_not_the_last_url_host(tmp_path):
    # Regression: the URL loop variable used to shadow the `host` parameter, so the
    # reported targeting host became whichever URL host was scanned last.
    dump = make_dump(tmp_path, b"https://go.microsoft.com/fwlink/?linkid=1\x00")

    report = analyze(dump, onion=None, host="1.2.3.4:5000", username=None)
    assert report["targeting"]["host"] == "1.2.3.4:5000"

    report = analyze(dump, onion="target.onion", host=None, username=None)
    assert report["targeting"]["host"] is None


def test_search_query_host_anchoring_keeps_real_drops_unrelated(tmp_path):
    real = b"http://target.onion/search?q=tharaka\x00"
    noise = b"some_unrelated_app.exe ?q=randomjunkterm\x00"
    dump = make_dump(tmp_path, real + noise)

    report = analyze(
        dump, onion="target.onion", host=None, username=None, source_type="full-memory"
    )
    values = [q["value"] for q in report["targeted"]["search_queries"]]
    assert "tharaka" in values
    assert "randomjunkterm" not in values
    assert report["host_anchoring"]["unanchored"]["search_queries"]["count"] == 1


def test_cookie_host_anchoring_never_applied_even_on_full_memory(tmp_path):
    # Real cookie: intentionally NOT co-located with any onion/host mention in the same
    # string, matching how Firefox's actual cookie-jar structure behaves in memory --
    # this is the exact case that regressed during development and must stay fixed.
    dump = make_dump(tmp_path, b"session=REALTOKEN123\x00http://target.onion/dashboard\x00")

    report = analyze(
        dump, onion="target.onion", host=None, username=None, source_type="full-memory"
    )
    values = [c["value"] for c in report["targeted"]["cookies"]]
    assert "REALTOKEN123" in values
    assert "cookies" not in report["host_anchoring"]["unanchored"]


def test_no_targets_leaves_host_anchoring_inactive_on_full_memory(tmp_path):
    dump = make_dump(tmp_path, b"user=alice password=hunter2\x00")
    report = analyze(dump, onion=None, host=None, username=None, source_type="full-memory")
    assert not report["host_anchoring"]["applied"]
    assert len(report["targeted"]["credentials"]) == 2


def test_download_path_regex_does_not_concatenate_repeated_paths(tmp_path):
    # Real bug: the same path written twice back-to-back with no separator made \b fail
    # right after the first extension (word-char 'e' meeting word-char 'C' is not a
    # boundary), so the old regex backtrack-extended into a second copy and reported
    # "...exeC:\...\...exe" as one bogus concatenated path. Reproduced on a real capture.
    doubled = rb"C:\Users\vboxuser\Downloads\Git-2.55.0.5-64-bit.exeC:\Users\vboxuser\Downloads\Git-2.55.0.5-64-bit.exe"
    dump = make_dump(tmp_path, doubled + b"\x00")
    report = analyze(dump, onion=None, host=None, username=None)
    values = [d["value"] for d in report["targeted"]["downloads"]]
    assert r"C:\Users\vboxuser\Downloads\Git-2.55.0.5-64-bit.exe" in values
    assert not any(v.count(":") > 1 for v in values)


def test_noise_value_filters_code_shaped_cookie_values(tmp_path):
    # Real bug: minified JS containing a literal "session=<code>" substring (destructuring/
    # chained-assignment syntax, no whitespace) was tagged high-confidence alongside a real
    # JWT session cookie. A real cookie/credential value never contains JS punctuation.
    dump = make_dump(
        tmp_path,
        b"session=eyJyb2xlIjoidXNlciJ9\x00"
        b"session=e}clear(){this.session.clearCache()}resetCacheControl(){this.setCacheControl(\x00"
        b"session=c[0],l.count=uo(c[2])+1,l.upgrade=uo(c[3]),l.upload=c.length\x00",
    )
    report = analyze(dump, onion=None, host=None, username=None)
    by_value = {c["value"]: c["confidence"] for c in report["targeted"]["cookies"]}
    assert by_value["eyJyb2xlIjoidXNlciJ9"] == "high"
    assert (
        by_value["e}clear(){this.session.clearCache()}resetCacheControl(){this.setCacheControl("]
        == "low"
    )
    assert by_value["c[0],l.count=uo(c[2])+1,l.upgrade=uo(c[3]),l.upload=c.length"] == "low"


def _u16(text: str) -> bytes:
    return text.encode("utf-16-le")


# Real layout seen in Firefox's heap: a field name as a one-byte string, a few binary
# bytes, then the typed value as UTF-16. Field name and value are never one string.
SEP = b"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0b\x0c\x0e"


def _login_form(user: str, password: str) -> bytes:
    return (
        b"\x00\x00"
        + b"username"
        + SEP
        + _u16(user)
        + SEP
        + b"password"
        + SEP
        + _u16(password)
        + SEP
    )


def test_iter_strings_yields_both_encodings_in_offset_order(tmp_path):
    from modules.module_c_memory.analyzer import iter_strings

    dump = make_dump(tmp_path, b"asciione" + SEP + _u16("utftwo!!") + SEP + b"asciithree")
    offsets = [o for o, _ in iter_strings(dump)]
    assert offsets == sorted(offsets)
    assert [s for _, s in iter_strings(dump)] == ["asciione", "utftwo!!", "asciithree"]


def test_adjacent_credentials_anchored_by_target_username(tmp_path):
    data = _login_form("alice.test", "S3cret-Pass-9") + b"X" * 8192  # no host nearby at all
    report = analyze(
        dump := make_dump(tmp_path, data),
        onion="target.onion",
        host=None,
        username="alice.test",
        source_type="full-memory",
    )
    assert dump.exists()
    found = {(c["field"], c["value"]) for c in report["targeted"]["credentials"]}
    assert ("username", "alice.test") in found
    assert ("password", "S3cret-Pass-9") in found
    assert all(c["shape"] == "adjacent" for c in report["targeted"]["credentials"])
    descriptions = {a["description"] for a in report["artifacts"]}
    assert "password=S3cret-Pass-9" in descriptions


def test_adjacent_credentials_anchored_by_nearby_target_host(tmp_path):
    data = b"http://target.onion/login\x00" + _login_form("someone", "Pw-12345-xyz")
    report = analyze(
        make_dump(tmp_path, data),
        onion="target.onion",
        host=None,
        username=None,
        source_type="full-memory",
    )
    anchors = {c["anchored_by"] for c in report["targeted"]["credentials"]}
    assert anchors == {"host"}
    assert ("password", "Pw-12345-xyz") in {
        (c["field"], c["value"]) for c in report["targeted"]["credentials"]
    }


def test_adjacent_credentials_far_from_target_are_kept_out(tmp_path):
    # Same shape from an unrelated process: no target username, no target host close by.
    data = (
        b"http://target.onion/login\x00"
        + b"Z" * (PROXIMITY_WINDOW * 3)
        + _login_form("stranger", "Other-Pass-1")
    )
    report = analyze(
        make_dump(tmp_path, data),
        onion="target.onion",
        host=None,
        username="alice.test",
        source_type="full-memory",
    )
    assert not report["targeted"]["credentials"]
    assert report["host_anchoring"]["unanchored"]["credentials"]["count"] == 2


def test_adjacent_credentials_need_a_target_to_anchor_to(tmp_path):
    report = analyze(
        make_dump(tmp_path, _login_form("alice.test", "S3cret-Pass-9")),
        onion=None,
        host=None,
        username=None,
    )
    assert not report["targeted"]["credentials"]


FORM = (
    b"subject=Thursday+delivery+access&email=t.maricourt%40harbourline.example"
    b"&message=Please+send+the+gate+code+for+berth+14."
)


def test_form_body_near_target_is_extracted_and_decoded(tmp_path):
    data = b"http://target.onion/contact\x00" + SEP + FORM + b"\x00" + SEP + FORM + b"\x00"
    report = analyze(
        make_dump(tmp_path, data),
        onion="target.onion",
        host=None,
        username=None,
        source_type="full-memory",
    )
    forms = report["targeted"]["form_submissions"]
    assert len(forms) == 1 and forms[0]["occurrences"] == 2
    assert forms[0]["anchored_by"] == "host"
    fields = {f["name"]: f["value"] for f in forms[0]["fields"]}
    assert fields["subject"] == "Thursday delivery access"
    assert fields["email"] == "t.maricourt@harbourline.example"
    description = next(
        a["description"] for a in report["artifacts"] if a["artifact_type"] == "form_submission"
    )
    assert "message='Please send the gate code for berth 14.'" in description


def test_form_body_far_from_target_is_dropped(tmp_path):
    data = b"http://target.onion/contact\x00" + b"Z" * (PROXIMITY_WINDOW * 3) + FORM + b"\x00"
    report = analyze(
        make_dump(tmp_path, data),
        onion="target.onion",
        host=None,
        username=None,
        source_type="full-memory",
    )
    assert report["targeted"]["form_submissions"] == []


def test_url_query_strings_and_flag_blobs_are_not_forms(tmp_path):
    data = (
        b"http://target.onion/search?q=ferry&page=2&sort=asc\x00"
        b"telemetry=1&enabled=true&count=42&ratio=7\x00"
    )
    report = analyze(
        make_dump(tmp_path, data),
        onion="target.onion",
        host=None,
        username=None,
        source_type="full-memory",
    )
    assert report["targeted"]["form_submissions"] == []


def _page(title: str, links: list[str]) -> bytes:
    body = "".join(f'<a href="{link}">x</a>\n' for link in links)
    return (
        f'<html>\n<head>\n  <title>{title}</title>\n  <link rel="stylesheet" '
        f'href="/static/style.css">\n</head>\n<body>\n{body}</body>\n</html>\n'
    ).encode()


TARGET_REQUESTS = b"".join(
    b"http://target.onion" + p + b"\x00"
    for p in (b"/about", b"/search", b"/login", b"/static/style.css")
)


def test_page_title_kept_when_page_links_to_paths_seen_on_target(tmp_path):
    data = TARGET_REQUESTS + _page("How to Reset Your Passphrase", ["/", "/search", "/login"])
    report = analyze(
        make_dump(tmp_path, data),
        onion="target.onion",
        host=None,
        username=None,
        source_type="full-memory",
    )
    titles = report["targeted"]["page_titles"]
    assert [t["title"] for t in titles] == ["How to Reset Your Passphrase"]
    assert "/static/style.css" in titles[0]["linked_target_paths"]
    assert any(a["artifact_type"] == "page_title" for a in report["artifacts"])


def test_page_title_of_a_foreign_page_is_not_kept(tmp_path):
    foreign = _page("Some Other Site", ["/blog", "/pricing", "/login"]).replace(
        b'  <link rel="stylesheet" href="/static/style.css">\n', b""
    )
    data = TARGET_REQUESTS + foreign
    report = analyze(
        make_dump(tmp_path, data),
        onion="target.onion",
        host=None,
        username=None,
        source_type="full-memory",
    )
    assert report["targeted"]["page_titles"] == []


def test_repeated_page_title_is_merged_with_a_count(tmp_path):
    page = _page("Search", ["/search", "/login"])
    report = analyze(
        make_dump(tmp_path, TARGET_REQUESTS + page + b"\x00" + page),
        onion="target.onion",
        host=None,
        username=None,
        source_type="full-memory",
    )
    titles = report["targeted"]["page_titles"]
    assert len(titles) == 1 and titles[0]["occurrences"] == 2


def test_firefox_origin_attributes_are_not_forms(tmp_path):
    data = (
        b"http://target.onion/\x00"
        b"privateBrowsingId=1&firstPartyDomain=target.onion&partitionKey=(http,target.onion)\x00"
        b"ngId=1&firstPartyDomain=target.onion\x00"
    )
    report = analyze(
        make_dump(tmp_path, data),
        onion="target.onion",
        host=None,
        username=None,
        source_type="full-memory",
    )
    assert report["targeted"]["form_submissions"] == []


def _big_dump(tmp_path: Path, pieces: dict[int, bytes], size: int = 70 * 1024 * 1024) -> Path:
    dump = tmp_path / "big.bin"
    with open(dump, "wb") as f:
        f.truncate(size)
        for offset, data in pieces.items():
            f.seek(offset)
            f.write(data)
    return dump


def _comparable(report: dict) -> str:
    import json

    report = dict(report)
    report.pop("generated_at")
    # One long run that straddles a sequential read window can be split differently from
    # the segment boundary; the string count is the only thing that can move.
    report["unfiltered"] = {
        k: v for k, v in report["unfiltered"].items() if k != "total_strings_extracted"
    }
    return json.dumps(report, sort_keys=True, default=str)


def test_parallel_scan_matches_sequential_across_segment_boundaries(tmp_path):
    boundary = 32 * 1024 * 1024  # SEGMENT_MIN_SIZE: where the second segment begins
    pieces = {
        0: b"http://target.onion/about\x00http://target.onion/search\x00"
        b"http://target.onion/static/style.css\x00",
        # A login pair whose field name is in segment 1 and whose value is in segment 2.
        boundary - 12: b"username" + SEP + _u16("alice.test") + SEP + b"password" + SEP,
        boundary + 60: _u16("S3cret-Pass-9"),
        # A page title just before the boundary whose links fall after it.
        boundary - 3000: b"\n<title>Boundary Page</title>\n",
        boundary
        + 100: b'\n<link href="/static/style.css">\n<a href="/search">s</a>\n<a href="/about">a</a>\n',
        # And an ordinary hit in the last segment.
        66 * 1024 * 1024: b"http://target.onion/library/rate-card\x00" + SEP + FORM + b"\x00",
    }
    dump = _big_dump(tmp_path, pieces)
    args = {
        "onion": "target.onion",
        "host": None,
        "username": "alice.test",
        "source_type": "full-memory",
    }

    sequential = analyze(dump, workers=1, **args)
    parallel = analyze(dump, workers=4, **args)

    assert _comparable(parallel) == _comparable(sequential)
    found = {(c["field"], c["value"]) for c in parallel["targeted"]["credentials"]}
    assert ("password", "S3cret-Pass-9") in found
    assert [t["title"] for t in parallel["targeted"]["page_titles"]] == ["Boundary Page"]
    assert len(parallel["targeted"]["form_submissions"]) == 1


def test_integrity_sidecar_mismatch_is_caught_in_parallel_mode(tmp_path):
    import pytest

    from core.exceptions import IntegrityError

    dump = _big_dump(tmp_path, {0: b"http://target.onion/x\x00"})
    (tmp_path / "big.bin.sha256").write_text("0" * 64 + "  big.bin\n")
    with pytest.raises(IntegrityError):
        analyze(dump, onion="target.onion", host=None, username=None, workers=4)


def test_integrity_sidecar_match_is_reported_in_parallel_mode(tmp_path):
    from core.hashing import hash_file

    dump = _big_dump(tmp_path, {0: b"http://target.onion/x\x00"})
    (tmp_path / "big.bin.sha256").write_text(hash_file(dump) + "  big.bin\n")
    report = analyze(dump, onion="target.onion", host=None, username=None, workers=4)
    assert report["dump"]["integrity_verified"] is True
    assert report["dump"]["sha256"] == hash_file(dump)


def _artifacts(report, kind):
    return [a["description"] for a in report["artifacts"] if a["artifact_type"] == kind]


def test_low_confidence_and_noise_hits_stay_out_of_artifacts_but_in_details(tmp_path):
    data = (
        b"http://target.onion/home\x00"
        b"session=%p]\x00"  # a printf format string, not a cookie
        b"file:///C:\x00"  # bare scheme, not a download
        b"C:\\Windows\\Temp\\other\\thing.txt\x00"  # a path, but not under Downloads
        b"C:\\Users\\bob\\Downloads\\report.pdf\x00"  # a real download
        b"http://target.onion/search?q=%s\x00"  # template placeholder, not a search
    )
    report = analyze(make_dump(tmp_path, data), onion="target.onion", host=None, username=None)
    assert _artifacts(report, "cookie") == []
    assert _artifacts(report, "download") == ["C:\\Users\\bob\\Downloads\\report.pdf"]
    assert _artifacts(report, "search_query") == []
    # nothing is thrown away: the raw observations are all still in details
    assert report["targeted"]["cookies"]
    assert {d["confidence"] for d in report["targeted"]["downloads"]} == {"low", "high"}
    assert report["targeted"]["search_queries"]


def test_a_finding_repeated_in_memory_is_one_artifact_with_every_offset_in_details(tmp_path):
    repeat = b"http://target.onion/library/rate-card\x00"
    report = analyze(
        make_dump(tmp_path, repeat * 5),
        onion="target.onion",
        host=None,
        username=None,
    )
    assert _artifacts(report, "url") == ["http://target.onion/library/rate-card"]
    assert len(report["targeted"]["urls"]) == 5


def test_a_login_pair_repeated_in_memory_is_one_credential_artifact(tmp_path):
    form = _login_form("alice.test", "S3cret-Pass-9")
    report = analyze(
        make_dump(tmp_path, (form + b"Z" * 300) * 3),
        onion="target.onion",
        host=None,
        username="alice.test",
        source_type="full-memory",
    )
    assert sorted(_artifacts(report, "credential")) == [
        "password=S3cret-Pass-9",
        "username=alice.test",
    ]


def test_cookie_names_are_an_input_not_a_hard_coded_list(tmp_path):
    data = b"Cookie: sid=abc123def; theme=dark; session=zzzzzz\x00http://target.onion/\x00"
    dump = make_dump(tmp_path, data)
    default = analyze(dump, onion="target.onion", host=None, username=None)
    assert {c["name"] for c in default["targeted"]["cookies"]} == {"session"}
    assert default["targeting"]["cookie_names"] == ["session", "trance_user", "trance_pref"]

    custom = analyze(dump, onion="target.onion", host=None, username=None, cookie_names=["sid"])
    assert [(c["name"], c["value"]) for c in custom["targeted"]["cookies"]] == [
        ("sid", "abc123def")
    ]
    assert _artifacts(custom, "cookie") == ["sid=abc123def"]
    assert custom["targeting"]["cookie_names"] == ["sid"]


def test_cookie_name_is_matched_literally_not_as_a_pattern(tmp_path):
    dump = make_dump(tmp_path, b"a.b=1 axb=2 http://target.onion/\x00")
    report = analyze(dump, onion="target.onion", host=None, username=None, cookie_names=["a.b"])
    assert [c["name"] for c in report["targeted"]["cookies"]] == ["a.b"]


def test_standalone_cli_passes_cookie_names_and_workers_through(tmp_path, monkeypatch, capsys):
    import json
    import sys

    from modules.module_c_memory import analyzer

    dump = make_dump(tmp_path, b"Cookie: sid=abc123def; http://target.onion/\x00")
    out = tmp_path / "report.json"
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "analyzer",
            str(dump),
            "--onion",
            "target.onion",
            "--cookie-name",
            "sid",
            "--workers",
            "1",
            "--output",
            str(out),
        ],
    )
    analyzer.main()
    report = json.loads(out.read_text())
    assert [c["name"] for c in report["targeted"]["cookies"]] == ["sid"]
    assert report["targeting"]["cookie_names"] == ["sid"]
    assert "JSON report written" in capsys.readouterr().out
