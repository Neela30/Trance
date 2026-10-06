import json
import subprocess
import sys
from pathlib import Path

import pytest

from gui import analysis_runner, mount_helper
from gui.analysis_request import AnalysisRequest

ROOT = Path(__file__).resolve().parents[1]


# -- analysis runner (child process protocol) ----------------------------------------


def test_parse_line_separates_protocol_messages_from_log_lines():
    progress = analysis_runner.PROTOCOL_PREFIX + json.dumps(
        {"type": "progress", "name": "module_b_disk", "step": 2, "total": 4}
    )
    assert analysis_runner.parse_line(progress) == (
        "progress",
        {"name": "module_b_disk", "step": 2, "total": 4},
    )
    assert analysis_runner.parse_line("[*] module_a_registry: ok") == (
        "log",
        "[*] module_a_registry: ok",
    )
    broken = analysis_runner.PROTOCOL_PREFIX + "{not json"
    assert analysis_runner.parse_line(broken) == ("log", broken)


def test_runner_command_relaunches_this_entry_point(monkeypatch):
    request = Path("/tmp/r.json")
    assert analysis_runner.runner_command(request)[1:] == [
        str(ROOT / "gui_main.py"),
        "--run-analysis",
        str(request),
    ]
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    assert analysis_runner.runner_command(request) == [
        sys.executable,
        "--run-analysis",
        str(request),
    ]


def test_child_process_runs_the_pipeline_and_reports_the_result(tmp_path):
    # The real child process, end to end: a downloads-only Module B run.
    scan_dir = tmp_path / "disk" / "downloads"
    scan_dir.mkdir(parents=True)
    scan = scan_dir / "zone_identifier_scan.json"
    scan.write_text(
        json.dumps(
            {
                "scan_method": "live_windows",
                "volume_root": "C:\\",
                "files_walked": 1,
                "scan_seconds": 0.0,
                "xattr_support": True,
                "internet_origin_files": [],
            }
        )
    )
    request = AnalysisRequest(
        case_name="child", output_dir=str(tmp_path / "out"), evidence_dir=str(tmp_path)
    )
    request_file = tmp_path / "request.json"
    request_file.write_text(request.to_json())

    completed = subprocess.run(
        analysis_runner.runner_command(request_file),
        capture_output=True,
        text=True,
        cwd=ROOT,
        timeout=120,
    )

    assert completed.returncode == 0, completed.stderr
    messages = [analysis_runner.parse_line(line) for line in completed.stdout.splitlines()]
    steps = [payload["step"] for kind, payload in messages if kind == "progress"]
    assert steps == [1, 2, 3, 4]
    [result] = [payload for kind, payload in messages if kind == "result"]
    summary = analysis_runner.summary_from(result)
    assert summary.report_path.is_file()
    assert summary.has_error is False
    findings = json.loads(summary.findings_path.read_text())
    assert findings["modules"]["module_b_disk"]["status"] == "ok"


def test_child_process_reports_a_bad_request_as_an_error(tmp_path):
    request_file = tmp_path / "request.json"
    request_file.write_text("{}")
    completed = subprocess.run(
        analysis_runner.runner_command(request_file),
        capture_output=True,
        text=True,
        cwd=ROOT,
        timeout=60,
    )
    assert completed.returncode == 1
    kinds = [analysis_runner.parse_line(line)[0] for line in completed.stdout.splitlines()]
    assert "error" in kinds


# -- mount helper (pure parts; the mount itself needs root) -------------------------


def _vdi(path: Path, image_type: int) -> Path:
    header = bytearray(512)
    header[0x40:0x44] = mount_helper.VDI_SIGNATURE.to_bytes(4, "little")
    header[0x4C:0x50] = image_type.to_bytes(4, "little")
    path.write_bytes(bytes(header))
    return path


def test_detect_format_reads_the_header(tmp_path):
    assert mount_helper.detect_format(_vdi(tmp_path / "flat.vdi", 1)) == "vdi"
    qcow = tmp_path / "x.img"
    qcow.write_bytes(b"QFI\xfb" + bytes(508))
    assert mount_helper.detect_format(qcow) == "qcow2"
    vhdx = tmp_path / "x.bin"
    vhdx.write_bytes(b"vhdxfile" + bytes(504))
    assert mount_helper.detect_format(vhdx) == "vhdx"
    raw = tmp_path / "disk.dd"
    raw.write_bytes(bytes(512))
    assert mount_helper.detect_format(raw) == "raw"


def test_detect_format_refuses_a_virtualbox_snapshot(tmp_path):
    with pytest.raises(mount_helper.HelperError, match="clonemedium"):
        mount_helper.detect_format(_vdi(tmp_path / "snap.vdi", mount_helper.VDI_DIFFERENCING))


def test_choose_partition_picks_the_largest_ntfs_volume():
    listing = {
        "blockdevices": [
            {
                "name": "nbd2",
                "size": 32 * 2**30,
                "fstype": None,
                "children": [
                    {"name": "nbd2p1", "size": 50 * 2**20, "fstype": "ntfs", "label": "System"},
                    {"name": "nbd2p2", "size": 31 * 2**30, "fstype": "ntfs", "label": None},
                    {"name": "nbd2p3", "size": 500 * 2**20, "fstype": "ntfs", "label": "Rec"},
                    {"name": "nbd2p4", "size": 40 * 2**30, "fstype": "ext4", "label": None},
                ],
            }
        ]
    }
    chosen, listed = mount_helper.choose_partition(listing)
    assert chosen == "nbd2p2"
    assert len(listed) == 4


def test_choose_partition_handles_a_bare_volume_and_no_ntfs():
    bare = {"blockdevices": [{"name": "nbd0", "size": 10, "fstype": "ntfs"}]}
    assert mount_helper.choose_partition(bare)[0] == "nbd0"
    with pytest.raises(mount_helper.HelperError, match="No NTFS partition"):
        mount_helper.choose_partition(
            {"blockdevices": [{"name": "nbd0", "children": [{"name": "nbd0p1", "fstype": "vfat"}]}]}
        )


def test_free_nbd_device_skips_busy_devices(tmp_path):
    for name, size, busy in (
        ("nbd0", "123", False),
        ("nbd1", "0", True),
        ("nbd10", "0", False),
        ("nbd2", "0", False),
    ):
        device = tmp_path / name
        device.mkdir()
        (device / "size").write_text(size)
        if busy:
            (device / "pid").write_text("1")
    assert mount_helper.free_nbd_device(tmp_path) == "nbd2"


def test_mount_helper_refuses_to_run_without_root(capsys):
    if hasattr(mount_helper.os, "geteuid") and mount_helper.os.geteuid() == 0:
        pytest.skip("running as root")
    assert mount_helper.main(["session", "/tmp/x.vdi"]) == 1
    assert "must run as root" in capsys.readouterr().out
    assert mount_helper.main(["bogus"]) == 2
