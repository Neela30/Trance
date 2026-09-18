import json
import subprocess
import sys

import pytest

from core.exceptions import AnalysisError
from modules.module_c_memory import volatility_analyze as va


def make_image(tmp_path):
    image = tmp_path / "image.raw"
    image.write_bytes(b"synthetic memory image bytes")
    return image


def test_analyze_missing_image_raises(tmp_path):
    with pytest.raises(AnalysisError, match="not found"):
        va.analyze(tmp_path / "nope.raw", vol_path="vol")


def test_analyze_missing_vol_binary_raises(tmp_path, monkeypatch):
    monkeypatch.setattr(va.shutil, "which", lambda name: None)
    with pytest.raises(AnalysisError, match="not found"):
        va.analyze(make_image(tmp_path), vol_path="vol")


def test_resolve_vol_binary_uses_which(monkeypatch):
    monkeypatch.setattr(va.shutil, "which", lambda name: f"/usr/bin/{name}")
    assert va._resolve_vol_binary("myvol") == "/usr/bin/myvol"
    assert va._resolve_vol_binary(None) == f"/usr/bin/{va.DEFAULT_VOL_BIN}"


def test_run_plugin_invokes_expected_command(tmp_path, monkeypatch):
    captured = {}

    def fake_run(cmd, capture_output, text, timeout):
        captured["cmd"] = cmd
        captured["timeout"] = timeout
        return subprocess.CompletedProcess(cmd, returncode=0, stdout="[]", stderr="")

    monkeypatch.setattr(va.subprocess, "run", fake_run)
    image = make_image(tmp_path)
    va.run_plugin("vol", image, "windows.psscan.PsScan", timeout=42)
    assert captured["cmd"] == ["vol", "-q", "-f", str(image), "-r", "json", "windows.psscan.PsScan"]
    assert captured["timeout"] == 42


def test_run_plugin_survives_timeout(tmp_path, monkeypatch):
    def fake_run(cmd, capture_output, text, timeout):
        raise subprocess.TimeoutExpired(cmd, timeout)

    monkeypatch.setattr(va.subprocess, "run", fake_run)
    result = va.run_plugin("vol", make_image(tmp_path), "windows.psscan.PsScan", timeout=5)
    assert result.returncode == -1
    assert "timed out" in result.stderr


def _mock_vol(monkeypatch, per_plugin_stdout: dict, per_plugin_returncode: dict | None = None):
    per_plugin_returncode = per_plugin_returncode or {}

    def fake_run(vol_bin, image_path, plugin, timeout=va.PLUGIN_TIMEOUT_SECONDS):
        rc = per_plugin_returncode.get(plugin, 0)
        stdout = per_plugin_stdout.get(plugin, "[]")
        return subprocess.CompletedProcess(
            [vol_bin, plugin], returncode=rc, stdout=stdout, stderr=""
        )

    monkeypatch.setattr(va, "run_plugin", fake_run)
    monkeypatch.setattr(va.shutil, "which", lambda name: f"/usr/bin/{name}")


def test_analyze_normalizes_rows_and_tags_source(tmp_path, monkeypatch):
    psscan_rows = [
        {
            "__children": [],
            "PID": 4321,
            "PPID": 4,
            "ImageFileName": "firefox.exe",
            "CreateTime": "2026-09-04T05:00:00",
            "ExitTime": None,
        }
    ]
    _mock_vol(monkeypatch, {"windows.psscan.PsScan": json.dumps(psscan_rows)})
    report = va.analyze(make_image(tmp_path), vol_path="vol", plugins=("windows.psscan.PsScan",))

    result = report["plugins"]["windows.psscan.PsScan"]
    assert result["status"] == "ok"
    assert result["row_count"] == 1
    row = result["rows"][0]
    assert row["source"] == "volatility3:windows.psscan.PsScan"
    assert "__children" not in row
    assert row["PID"] == 4321


def test_analyze_isolates_one_plugin_failure_from_the_rest(tmp_path, monkeypatch):
    _mock_vol(
        monkeypatch,
        per_plugin_stdout={
            "windows.psscan.PsScan": json.dumps([{"__children": [], "PID": 1}]),
            "windows.netscan.NetScan": "not valid json",
        },
        per_plugin_returncode={"windows.netscan.NetScan": 1},
    )
    report = va.analyze(
        make_image(tmp_path),
        vol_path="vol",
        plugins=("windows.psscan.PsScan", "windows.netscan.NetScan"),
    )

    assert report["plugins"]["windows.psscan.PsScan"]["status"] == "ok"
    assert report["plugins"]["windows.psscan.PsScan"]["row_count"] == 1
    assert report["plugins"]["windows.netscan.NetScan"]["status"] == "error"
    assert report["plugins"]["windows.netscan.NetScan"]["message"]


def test_analyze_treats_non_list_json_as_plugin_error(tmp_path, monkeypatch):
    _mock_vol(monkeypatch, {"windows.psscan.PsScan": json.dumps({"not": "a list"})})
    report = va.analyze(make_image(tmp_path), vol_path="vol", plugins=("windows.psscan.PsScan",))
    assert report["plugins"]["windows.psscan.PsScan"]["status"] == "error"


def test_format_summary_reports_ok_and_failed_plugins(tmp_path, monkeypatch):
    _mock_vol(
        monkeypatch,
        per_plugin_stdout={
            "windows.psscan.PsScan": json.dumps([{"__children": []}]),
            "windows.netscan.NetScan": "bad json",
        },
        per_plugin_returncode={"windows.netscan.NetScan": 1},
    )
    report = va.analyze(
        make_image(tmp_path),
        vol_path="vol",
        plugins=("windows.psscan.PsScan", "windows.netscan.NetScan"),
    )
    summary = va.format_summary(report)
    assert "windows.psscan.PsScan: 1 row(s)" in summary
    assert "windows.netscan.NetScan: FAILED" in summary


def test_cli_requires_image_argument(monkeypatch):
    monkeypatch.setattr(sys, "argv", ["volatility_analyze.py"])
    with pytest.raises(SystemExit):
        va.main()
