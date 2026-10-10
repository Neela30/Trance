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
