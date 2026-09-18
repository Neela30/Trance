from pathlib import Path

from modules.module_c_memory.analyzer import analyze


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
