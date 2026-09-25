import json

import analyze_evidence


def _base_args(**overrides):
    defaults = {
        "case": "c1",
        "output_dir": "output",
        "evidence_dir": None,
        "verbose": False,
        "ntuser": None,
        "system": None,
        "amcache": None,
        "disk_profile": None,
        "tor_dir": None,
        "disk_image": None,
        "disk_root": None,
        "dump": None,
        "source_type": None,
        "onion": None,
        "host": None,
        "username": None,
        "vol3_path": None,
        "vol3_extract_process": None,
        "vol3_extract_pid": None,
    }
    defaults.update(overrides)
    return type("Args", (), defaults)()


def test_resolve_from_manifest_prefers_full_image_over_live_dump(tmp_path):
    manifest = {
        "registry": {"SYSTEM": {"status": "ok", "path": "registry/SYSTEM_x"}},
        "memory": {
            "live_dump": {"status": "ok", "path": "memory/firefox_1_x.bin"},
            "full_image": {"status": "ok", "path": "memory/fullmem_x.raw"},
        },
        "disk": {"profile": {"status": "ok", "path": "disk/profile"}},
    }
    (tmp_path / "acquire_manifest.json").write_text(json.dumps(manifest))

    resolved = analyze_evidence.resolve_evidence(tmp_path)

    assert resolved["system"] == "registry/SYSTEM_x"
    assert resolved["dump"] == "memory/fullmem_x.raw"
    assert resolved["source_type"] == "full-memory"
    assert resolved["disk_profile"] == "disk/profile"


def test_resolve_from_manifest_falls_back_to_live_dump(tmp_path):
    manifest = {
        "registry": {},
        "memory": {"live_dump": {"status": "ok", "path": "memory/firefox_1_x.bin"}},
        "disk": {},
    }
    (tmp_path / "acquire_manifest.json").write_text(json.dumps(manifest))

    resolved = analyze_evidence.resolve_evidence(tmp_path)

    assert resolved["dump"] == "memory/firefox_1_x.bin"
    assert resolved["source_type"] == "process"


def test_resolve_from_manifest_skips_failed_categories(tmp_path):
    manifest = {"registry": {"status": "error", "message": "boom"}, "memory": {}, "disk": {}}
    (tmp_path / "acquire_manifest.json").write_text(json.dumps(manifest))

    resolved = analyze_evidence.resolve_evidence(tmp_path)

    assert "system" not in resolved
    assert "ntuser" not in resolved


def test_resolve_by_globbing_picks_latest_and_prefers_full_image(tmp_path):
    registry = tmp_path / "registry"
    registry.mkdir()
    (registry / "SYSTEM_20260101T000000Z").write_bytes(b"old")
    (registry / "SYSTEM_20260102T000000Z").write_bytes(b"new")

    memory = tmp_path / "memory"
    memory.mkdir()
    (memory / "firefox_1_20260101T000000Z.bin").write_bytes(b"process dump")
    (memory / "fullmem_20260101T000000Z.raw").write_bytes(b"full image")

    resolved = analyze_evidence.resolve_evidence(tmp_path)

    assert resolved["system"].endswith("SYSTEM_20260102T000000Z")
    assert resolved["dump"].endswith(".raw")
    assert resolved["source_type"] == "full-memory"


def test_resolve_by_globbing_falls_back_to_flat_layout(tmp_path):
    # No registry/ or memory/ subfolders -- e.g. the individual acquire scripts run
    # directly and their output copied off a VM as one flat folder, predating
    # acquire_all.py's subfolder layout.
    (tmp_path / "SYSTEM_20260918T170509Z").write_bytes(b"hive bytes")
    (tmp_path / "NTUSER_20260918T170509Z.DAT").write_bytes(b"hive bytes")
    (tmp_path / "Amcache_20260918T170509Z.hve").write_bytes(b"hive bytes")
    (tmp_path / "firefox_5368_20260904T050334Z.bin").write_bytes(b"dump bytes")

    resolved = analyze_evidence.resolve_evidence(tmp_path)

    assert resolved["system"].endswith("SYSTEM_20260918T170509Z")
    assert resolved["ntuser"].endswith("NTUSER_20260918T170509Z.DAT")
    assert resolved["amcache"].endswith("Amcache_20260918T170509Z.hve")
    assert resolved["dump"].endswith("firefox_5368_20260904T050334Z.bin")
    assert resolved["source_type"] == "process"


def test_resolve_by_globbing_does_not_mistake_sha256_sidecar_for_the_system_hive(tmp_path):
    # "SYSTEM_*" (no extension on the hive itself) also matches its own "SYSTEM_x.sha256"
    # sidecar, which is usually the more-recently-written file -- _latest() must not
    # hand back the sidecar text file as if it were the hive.
    hive = tmp_path / "SYSTEM_20260918T170509Z"
    hive.write_bytes(b"hive bytes")
    (tmp_path / "SYSTEM_20260918T170509Z.sha256").write_text("deadbeef  SYSTEM_x\n")

    resolved = analyze_evidence.resolve_evidence(tmp_path)

    assert resolved["system"] == str(hive)


def test_resolve_by_globbing_finds_disk_dirs(tmp_path):
    (tmp_path / "disk" / "profile").mkdir(parents=True)
    (tmp_path / "disk" / "tor_dir").mkdir(parents=True)

    resolved = analyze_evidence.resolve_evidence(tmp_path)

    assert resolved["disk_profile"].endswith("disk/profile")
    assert resolved["tor_dir"].endswith("disk/tor_dir")


def test_build_argv_uses_resolved_paths(tmp_path):
    args = _base_args(evidence_dir=tmp_path, onion="abc.onion")
    resolved = {"system": "registry/SYSTEM_x", "dump": "memory/x.bin", "source_type": "process"}

    argv = analyze_evidence.build_argv(args, resolved)

    assert "--system" in argv
    assert argv[argv.index("--system") + 1] == "registry/SYSTEM_x"
    assert "--dump" in argv
    assert "--source-type" in argv
    assert "--onion" in argv
    assert argv[argv.index("--onion") + 1] == "abc.onion"


def test_build_argv_passes_through_disk_root(tmp_path):
    args = _base_args(evidence_dir=tmp_path, disk_root=tmp_path / "mnt" / "evidence-volume")

    argv = analyze_evidence.build_argv(args, {})

    assert "--disk-root" in argv
    assert argv[argv.index("--disk-root") + 1] == str(tmp_path / "mnt" / "evidence-volume")


def test_build_argv_explicit_flag_overrides_resolved_path(tmp_path):
    args = _base_args(evidence_dir=tmp_path, system=tmp_path / "explicit-SYSTEM")
    resolved = {"system": "registry/SYSTEM_from_manifest"}

    argv = analyze_evidence.build_argv(args, resolved)

    assert argv[argv.index("--system") + 1] == str(tmp_path / "explicit-SYSTEM")


def test_build_argv_omits_flags_with_no_value(tmp_path):
    args = _base_args(evidence_dir=tmp_path)
    argv = analyze_evidence.build_argv(args, {})
    assert "--system" not in argv
    assert "--dump" not in argv


def test_main_delegates_to_main_module(tmp_path, monkeypatch):
    captured = {}

    def fake_main(argv):
        captured["argv"] = argv
        return 0

    monkeypatch.setattr(analyze_evidence.main_module, "main", fake_main)
    (tmp_path / "disk" / "profile").mkdir(parents=True)

    exit_code = analyze_evidence.main(["--case", "c1", "--evidence-dir", str(tmp_path)])

    assert exit_code == 0
    assert "--disk-profile" in captured["argv"]
    assert "--case" in captured["argv"]
