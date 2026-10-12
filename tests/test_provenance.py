import json
import re
from pathlib import Path

import main
import report
from core import provenance
from core.config import TranceConfig
from core.hashing import hash_bytes, hash_file
from core.schema import ModuleResult
from core.version import __version__

REPO_ROOT = Path(__file__).resolve().parent.parent


def _write(path: Path, data: bytes, sidecar: str | None = "match") -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    if sidecar == "match":
        path.with_name(path.name + ".sha256").write_text(f"{hash_bytes(data)}  {path.name}\n")
    elif sidecar == "wrong":
        path.with_name(path.name + ".sha256").write_text(f"{'0' * 64}  {path.name}\n")
    return path


def _folder(root: Path, files: dict[str, bytes]) -> Path:
    root.mkdir(parents=True)
    lines = []
    for name, data in files.items():
        (root / name).write_bytes(data)
        lines.append(f"{hash_bytes(data)}  {name}")
    (root / "hashes.sha256").write_text("\n".join(lines) + "\n")
    return root


def _by_label(items: list[dict]) -> dict[str, dict]:
    return {i["label"]: i for i in items}


def test_version_matches_pyproject():
    text = (REPO_ROOT / "pyproject.toml").read_text()
    assert re.search(r'^version = "([^"]+)"', text, re.MULTILINE).group(1) == __version__


def test_file_matching_its_sidecar_is_verified(tmp_path):
    hive = _write(tmp_path / "SYSTEM_x", b"regf-system")
    items = provenance.evidence_items({"module_a_registry": {"system": hive}}, [])
    (item,) = items
    assert item["status"] == "verified"
    assert item["sha256"] == item["acquisition_sha256"] == hash_bytes(b"regf-system")
    assert item["size_bytes"] == len(b"regf-system")
    assert item["label"] == "SYSTEM registry hive"


def test_file_changed_since_acquisition_is_a_mismatch(tmp_path):
    hive = _write(tmp_path / "NTUSER.DAT", b"changed", sidecar="wrong")
    (item,) = provenance.evidence_items({"module_a_registry": {"ntuser": hive}}, [])
    assert item["status"] == "MISMATCH"
    assert item["acquisition_sha256"] == "0" * 64


def test_file_without_sidecar_is_unrecorded_but_still_hashed(tmp_path):
    hive = _write(tmp_path / "Amcache.hve", b"amcache", sidecar=None)
    (item,) = provenance.evidence_items({"module_a_registry": {"amcache": hive}}, [])
    assert item["status"] == "unrecorded"
    assert item["sha256"] == hash_bytes(b"amcache")


def test_file_listed_in_its_folders_hashes_manifest_is_verified(tmp_path):
    folder = _folder(tmp_path / "downloads", {"zone_identifier_scan.json": b"{}"})
    scan = folder / "zone_identifier_scan.json"
    (item,) = provenance.evidence_items({"module_b_disk": {"downloads_scan": scan}}, [])
    assert item["status"] == "verified"


def test_missing_input_is_reported_missing(tmp_path):
    (item,) = provenance.evidence_items({"module_a_registry": {"system": tmp_path / "gone"}}, [])
    assert item["status"] == "missing"


def test_memory_image_hash_is_reused_from_module_c_not_read_again(tmp_path, monkeypatch):
    image = _write(tmp_path / "fullmem.raw", b"ram")
    result = ModuleResult(
        module="module_c_memory",
        status="ok",
        details={"dump": {"path": str(image), "sha256": hash_bytes(b"ram")}},
    )
    monkeypatch.setattr(provenance, "hash_file", lambda p: (_ for _ in ()).throw(AssertionError))
    (item,) = provenance.evidence_items({"module_c_memory": {"dump": image}}, [result])
    assert item["status"] == "verified"
    assert item["hashed_by"] == "module"


def test_folder_items_come_from_module_bs_own_verification(tmp_path):
    profile = _folder(tmp_path / "profile", {"places.sqlite": b"p", "cookies.sqlite": b"c"})
    verification = {
        "places.sqlite": {"status": "match", "recorded": "a" * 64, "actual": "a" * 64},
        "cookies.sqlite": {"status": "MISMATCH", "recorded": "b" * 64, "actual": "c" * 64},
    }
    result = ModuleResult(
        module="module_b_disk",
        status="error",
        details={"profile": {"hash_verification": verification}},
    )
    items = provenance.evidence_items({"module_b_disk": {"profile_dir": profile}}, [result])
    statuses = {Path(i["path"]).name: i["status"] for i in items}
    assert statuses == {"cookies.sqlite": "MISMATCH", "places.sqlite": "verified"}


def test_folder_is_verified_here_when_module_b_did_not_get_that_far(tmp_path):
    tor_dir = _folder(tmp_path / "tor_dir", {"state": b"s", "torrc": b"t"})
    items = provenance.evidence_items({"module_b_disk": {"tor_dir": tor_dir}}, [])
    assert [i["status"] for i in items] == ["verified", "verified"]
    assert {i["label"] for i in items} == {"Tor daemon data folder"}


def test_mounted_volume_is_listed_but_not_hashed(tmp_path):
    (item,) = provenance.evidence_items({"module_b_disk": {"disk_root": tmp_path}}, [])
    assert item["status"] == "not_hashed"
    assert item["kind"] == "volume"


def test_acquisition_info_reads_the_manifest(tmp_path):
    manifest = {
        "acquired_at": "2026-10-09T18:24:44+00:00",
        "acquired_by": {"tool": "trance-acquire", "version": "0.1.0", "hostname": "WIN10"},
        "memory": {"full_image": {"winpmem_path": "D:\\winpmem.exe", "winpmem_sha256": "f" * 64}},
        "registry": {"custody_log_path": "registry/registry_acquire.custody.json"},
        "disk": {"custody_log_path": "disk/disk.custody.json", "ntfs": {}},
    }
    (tmp_path / "acquire_manifest.json").write_text(json.dumps(manifest))
    info = provenance.acquisition_info(tmp_path)
    assert info["acquired_at"] == manifest["acquired_at"]
    assert info["acquired_by"]["hostname"] == "WIN10"
    assert info["winpmem_sha256"] == "f" * 64
    assert info["custody_logs"] == [
        "registry/registry_acquire.custody.json",
        "disk/disk.custody.json",
    ]
    assert info["manifest_sha256"] == hash_file(tmp_path / "acquire_manifest.json")


def test_acquisition_info_is_none_without_a_manifest(tmp_path):
    assert provenance.acquisition_info(tmp_path) is None
    assert provenance.acquisition_info(None) is None


def test_tool_info_names_the_version():
    info = provenance.tool_info()
    assert info["name"] == "TRANCE"
    assert info["version"] == __version__


def test_pipeline_writes_provenance_and_report_prints_findings_hash(tmp_path):
    hive = _write(tmp_path / "evidence" / "SYSTEM_x", b"not a real hive")
    config = TranceConfig(case_name="c1", output_dir=tmp_path / "out")
    kwargs = {"module_a_registry": {"system": hive}, "module_b_disk": {}, "module_c_memory": {}}

    pipeline = main.run_pipeline(config, kwargs)

    prov = pipeline.findings["provenance"]
    assert prov["tool"]["version"] == __version__
    assert prov["evidence_items"][0]["status"] == "verified"
    assert prov["evidence_summary"] == {"verified": 1}
    html = pipeline.report_path.read_text()
    assert hash_file(pipeline.findings_path) in html
    assert "Evidence examined" in html
    assert "Analysis provenance" in html


def test_report_flags_an_evidence_item_that_did_not_verify():
    findings = {
        "schema_version": 1,
        "case": {"name": "c1", "output_dir": "out", "evidence_dir": None},
        "generated_at": "2026-10-12T00:00:00+00:00",
        "modules": {},
        "artifacts": [],
        "provenance": {
            "tool": {"name": "TRANCE", "version": "0.1.0", "git_commit": None},
            "runtime": {"python": "3.12", "platform": "Linux", "hostname": "h", "libraries": {}},
            "analysis_started_at": "a",
            "analysis_finished_at": "b",
            "acquisition": None,
            "evidence_items": [
                {
                    "label": "SYSTEM registry hive",
                    "path": "SYSTEM_x",
                    "size_bytes": 3,
                    "sha256": "1" * 64,
                    "acquisition_sha256": "2" * 64,
                    "status": "MISMATCH",
                }
            ],
        },
    }
    html = report.render_report(findings)
    assert "did not verify" in html
    assert "2" * 64 in html


def test_print_stylesheet_puts_case_page_and_findings_hash_on_every_page():
    findings = {
        "schema_version": 1,
        "case": {"name": "c1", "output_dir": "out", "evidence_dir": None},
        "generated_at": "2026-10-12T00:00:00+00:00",
        "modules": {},
        "artifacts": [],
    }
    html = report.render_report(findings, findings_sha256="ab" * 32)
    assert '@top-left { content: "TRANCE · Case c1"' in html
    assert '"findings.json SHA-256 ' + "ab" * 32 + '"' in html
    assert 'counter(page) " of " counter(pages)' in html
    assert "@media print" in html


def test_css_string_cannot_break_out_of_the_style_block():
    value = report._css_string('a"b\\c</style><script>')
    assert "</style>" not in value
    assert '"' not in value[1:-1]
    assert value.startswith('"') and value.endswith('"')
