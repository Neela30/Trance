from modules.module_c_memory.analyzer import analyze
from modules.module_c_memory.report import build_context


def base_details(tmp_path, host="127.0.0.1:5000", username=None):
    dump = tmp_path / "d.bin"
    dump.write_bytes(
        b"http://127.0.0.1:5000/login\x00" * 2
        + b"session=REALTOKEN123\x00"
        + b"C:\\Users\\alice\\Downloads\\evidence_report.txt\x00"
    )
    return analyze(dump, onion=None, host=host, username=username)


def test_missing_volatility3_key_degrades_to_skipped(tmp_path):
    details = base_details(tmp_path)
    ctx = build_context(details)
    assert ctx["volatility3"]["status"] == "skipped"
    assert ctx["volatility3"]["plugins"] == []


def test_error_status_and_message_passed_through(tmp_path):
    details = base_details(tmp_path)
    details["volatility3"] = {"status": "error", "message": "vol binary not found", "plugins": {}}
    ctx = build_context(details)
    assert ctx["volatility3"]["status"] == "error"
    assert ctx["volatility3"]["message"] == "vol binary not found"


def test_plugin_views_labeled_capped_and_ordered(tmp_path):
    details = base_details(tmp_path)
    many_rows = [
        {"source": "volatility3:windows.filescan.FileScan", "Offset": hex(i), "Name": f"f{i}"}
        for i in range(150)
    ]
    details["volatility3"] = {
        "status": "ok",
        "message": None,
        "vol_bin": "vol",
        "plugins": {
            "windows.registry.hivelist.HiveList": {
                "status": "error",
                "message": "no symbols",
                "row_count": 0,
                "rows": [],
            },
            "windows.psscan.PsScan": {
                "status": "ok",
                "message": None,
                "row_count": 1,
                "rows": [
                    {
                        "source": "volatility3:windows.psscan.PsScan",
                        "PID": 1,
                        "ImageFileName": "firefox.exe",
                    }
                ],
            },
            "windows.filescan.FileScan": {
                "status": "ok",
                "message": None,
                "row_count": 150,
                "rows": many_rows,
            },
        },
    }
    ctx = build_context(details)
    plugins = ctx["volatility3"]["plugins"]
    # Known plugins render in the fixed VOL3_PLUGIN_LABELS order, not dict insertion order.
    names = [p["name"] for p in plugins]
    assert names.index("windows.psscan.PsScan") < names.index("windows.filescan.FileScan")
    assert names.index("windows.filescan.FileScan") < names.index(
        "windows.registry.hivelist.HiveList"
    )

    filescan = next(p for p in plugins if p["name"] == "windows.filescan.FileScan")
    assert filescan["label"] == "Open files (filescan)"
    assert filescan["total_rows"] == 150
    assert len(filescan["rows"]) == 100  # VOL3_TABLE_CAP
    assert filescan["truncated"] is True

    hivelist = next(p for p in plugins if p["name"] == "windows.registry.hivelist.HiveList")
    assert hivelist["status"] == "error"
    assert hivelist["message"] == "no symbols"


def test_psscan_corroboration_flags_firefox_process(tmp_path):
    details = base_details(tmp_path)
    details["volatility3"] = {
        "status": "ok",
        "message": None,
        "vol_bin": "vol",
        "plugins": {
            "windows.psscan.PsScan": {
                "status": "ok",
                "message": None,
                "row_count": 2,
                "rows": [
                    {
                        "source": "s",
                        "PID": 111,
                        "ImageFileName": "firefox.exe",
                        "CreateTime": "t1",
                        "ExitTime": "t2",
                    },
                    {
                        "source": "s",
                        "PID": 222,
                        "ImageFileName": "explorer.exe",
                        "CreateTime": "t3",
                        "ExitTime": None,
                    },
                ],
            }
        },
    }
    ctx = build_context(details)
    notes = ctx["volatility3"]["corroboration"]
    assert len(notes) == 1
    assert "PID 111" in notes[0]
    assert "exited t2" in notes[0]
    assert "explorer" not in notes[0]


def test_netscan_corroboration_requires_host_and_port_match(tmp_path):
    details = base_details(tmp_path, host="127.0.0.1:5000")
    details["volatility3"] = {
        "status": "ok",
        "message": None,
        "vol_bin": "vol",
        "plugins": {
            "windows.netscan.NetScan": {
                "status": "ok",
                "message": None,
                "row_count": 2,
                "rows": [
                    {
                        "source": "s",
                        "LocalAddr": "10.0.0.5",
                        "LocalPort": 1,
                        "ForeignAddr": "127.0.0.1",
                        "ForeignPort": 5000,
                        "Proto": "TCPv4",
                        "State": "ESTABLISHED",
                        "PID": 1,
                    },
                    {
                        "source": "s",
                        "LocalAddr": "10.0.0.5",
                        "LocalPort": 2,
                        "ForeignAddr": "127.0.0.1",
                        "ForeignPort": 9999,
                        "Proto": "TCPv4",
                        "State": "CLOSED",
                        "PID": 2,
                    },
                ],
            }
        },
    }
    ctx = build_context(details)
    notes = ctx["volatility3"]["corroboration"]
    assert len(notes) == 1
    assert "PID 1" in notes[0]


def test_filescan_corroboration_matches_confirmed_download_basename(tmp_path):
    details = base_details(tmp_path)
    assert details["key_findings"]["downloads"], "fixture must produce a confirmed download"
    details["volatility3"] = {
        "status": "ok",
        "message": None,
        "vol_bin": "vol",
        "plugins": {
            "windows.filescan.FileScan": {
                "status": "ok",
                "message": None,
                "row_count": 2,
                "rows": [
                    {
                        "source": "s",
                        "Offset": "0x1",
                        "Name": "\\Users\\alice\\Downloads\\evidence_report.txt",
                    },
                    {"source": "s", "Offset": "0x2", "Name": "\\Windows\\System32\\unrelated.dll"},
                ],
            }
        },
    }
    ctx = build_context(details)
    notes = ctx["volatility3"]["corroboration"]
    assert len(notes) == 1
    assert "evidence_report.txt" in notes[0]


def test_downloads_split_matched_unmatched_on_full_memory(tmp_path):
    dump = tmp_path / "d.bin"
    dump.write_bytes(
        b"http://target.onion/login\x00"
        b"http://target.onion/download/evidence_report.txt\x00"
        b"C:\\Users\\alice\\Downloads\\evidence_report.txt\x00"
        b"C:\\Users\\bob\\Downloads\\unrelated_installer.exe\x00"
    )
    details = analyze(
        dump, onion="target.onion", host=None, username=None, source_type="full-memory"
    )
    ctx = build_context(details)
    matched_values = {d["value"] for d in ctx["downloads"]["matched"]}
    unmatched_values = {d["value"] for d in ctx["downloads"]["unmatched"]}
    assert any("evidence_report.txt" in v for v in matched_values)
    assert any("unrelated_installer.exe" in v for v in unmatched_values)
    assert not any("unrelated_installer.exe" in v for v in matched_values)


def test_downloads_not_split_on_process_source_type(tmp_path):
    details = base_details(tmp_path)  # source_type="process" by default
    ctx = build_context(details)
    assert ctx["downloads"]["unmatched"] == []
    assert len(ctx["downloads"]["matched"]) == len(details["key_findings"]["downloads"])


def test_no_corroboration_notes_when_nothing_lines_up(tmp_path):
    details = base_details(tmp_path)
    details["volatility3"] = {
        "status": "ok",
        "message": None,
        "vol_bin": "vol",
        "plugins": {
            "windows.psscan.PsScan": {
                "status": "ok",
                "message": None,
                "row_count": 1,
                "rows": [
                    {
                        "source": "s",
                        "PID": 1,
                        "ImageFileName": "explorer.exe",
                        "CreateTime": "t",
                        "ExitTime": None,
                    }
                ],
            },
        },
    }
    ctx = build_context(details)
    assert ctx["volatility3"]["corroboration"] == []


# --- Tor Browser processes from psscan (real c3 shapes: every parent had already exited) ---


def _ps(name, pid, ppid, created, exited=None):
    return {
        "ImageFileName": name,
        "PID": pid,
        "PPID": ppid,
        "CreateTime": created,
        "ExitTime": exited,
    }


C3_PSSCAN = [
    _ps("firefox.exe", 5944, 632, "2026-10-09T18:02:13+00:00", "2026-10-09T18:05:49+00:00"),
    _ps("firefox.exe", 6884, 5976, "2026-10-09T18:03:28+00:00", "2026-10-09T18:05:22+00:00"),
    _ps("firefox.exe", 4952, 5976, "2026-10-09T18:03:30+00:00", "2026-10-09T18:05:22+00:00"),
    _ps("firefox.exe", 7160, 4828, "2026-10-09T18:06:12+00:00", "2026-10-09T18:15:59+00:00"),
    _ps("svchost.exe", 1612, 600, "2026-10-09T17:56:52+00:00"),
    # Boot-time processes stamped by a clock that was 12 hours off.
    _ps("System", 4, 0, "2026-10-10T06:25:34+00:00"),
    _ps("smss.exe", 336, 4, "2026-10-10T06:25:34+00:00"),
]
IMAGE = "/evidence/c3-r01/memory/fullmem_20261009T182529Z.raw"


def test_browser_processes_are_grouped_by_parent_with_their_times():
    from modules.module_c_memory.report import _process_activity

    activity = _process_activity(C3_PSSCAN, IMAGE)
    groups = [(g["parent_pid"], g["count"]) for g in activity["groups"]]
    assert groups == [(632, 1), (5976, 2), (4828, 1)]
    assert activity["first_start"].isoformat() == "2026-10-09T18:02:13+00:00"
    assert activity["last_exit"].isoformat() == "2026-10-09T18:15:59+00:00"
    assert activity["still_running"] is False
    assert activity["process_count"] == 4  # svchost is not a browser process


def test_processes_created_after_the_capture_are_clock_anomalies_not_activity():
    from modules.module_c_memory.report import _process_activity

    activity = _process_activity(C3_PSSCAN, IMAGE)
    assert [a["pid"] for a in activity["clock_anomalies"]] == [4, 336]
    assert activity["capture_time"].isoformat() == "2026-10-09T18:25:29+00:00"
    # A process started while the image was being written is not an anomaly.
    during = [
        _ps("firefox.exe", 7160, 4828, "2026-10-09T18:06:12+00:00"),
        _ps("winpmem.exe", 900, 1, "2026-10-09T18:26:00+00:00"),
    ]
    assert _process_activity(during, IMAGE)["clock_anomalies"] == []
    # Nothing browser-related and nothing anomalous: nothing to report.
    assert _process_activity([_ps("svchost.exe", 1, 0, "2026-10-09T17:00:00+00:00")], IMAGE) is None


def test_without_a_capture_timestamp_no_clock_check_is_made():
    from modules.module_c_memory.report import _process_activity

    activity = _process_activity(C3_PSSCAN, "/evidence/memory.raw")
    assert activity["capture_time"] is None
    assert activity["clock_anomalies"] == []


def test_a_browser_still_running_at_capture_has_no_end_time():
    from modules.module_c_memory.report import _process_activity

    rows = [_ps("firefox.exe", 7160, 4828, "2026-10-09T15:26:30+00:00")]
    activity = _process_activity(rows, "fullmem_20261009T154539Z.raw")
    assert activity["still_running"] is True
    assert activity["last_exit"] is None
    assert activity["groups"][0]["still_running"] is True


def test_capture_time_reads_windows_and_posix_paths():
    from modules.module_c_memory.report import _capture_time

    for path in (
        r"C:\evidence\memory\fullmem_20261009T182529Z.raw",
        "/home/x/memory/fullmem_20261009T182529Z.raw",
    ):
        assert _capture_time(path).isoformat() == "2026-10-09T18:25:29+00:00"
