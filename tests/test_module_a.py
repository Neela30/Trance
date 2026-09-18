"""Tests for Module A (Registry & Execution Evidence).

Per Module A Description 2.6 (Testing Approach): unit tests never touch
real evidence. Everything here either exercises pure functions with no
file I/O, or runs the pipeline against a small temp file standing in for a
hive with the regipy-calling extractors mocked out — never a real
NTUSER.DAT/SYSTEM/Amcache.hve.
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

import pytest

from core.config import TranceConfig
from core.exceptions import IntegrityError, ParsingError
from core.schema import Artifact
from modules.module_a_registry.constants import (
    ARTIFACT_TYPE_AMCACHE,
    ARTIFACT_TYPE_RECENTDOCS,
    ARTIFACT_TYPE_SHIMCACHE,
    ARTIFACT_TYPE_USER_ASSIST,
    candidate_path,
    is_tor_related,
)
from modules.module_a_registry.normalize import normalize_entry
from modules.module_a_registry.pipeline import run_module_a, write_output

# ---------------------------------------------------------------------------
# is_tor_related() — pure, no file I/O
# ---------------------------------------------------------------------------


class TestIsTorRelated:
    def test_matches_tor_browser_install_path(self):
        path = r"C:\Users\bob\Desktop\Tor Browser\Browser\firefox.exe"
        assert is_tor_related(path) is True

    def test_matches_case_insensitively(self):
        path = r"C:\USERS\BOB\DESKTOP\TOR BROWSER\BROWSER\FIREFOX.EXE"
        assert is_tor_related(path) is True

    def test_matches_forward_slash_paths(self):
        path = "C:/Users/bob/Desktop/Tor Browser/Browser/firefox.exe"
        assert is_tor_related(path) is True

    def test_matches_bridge_binary_by_basename_alone(self):
        assert is_tor_related(r"C:\Users\bob\AppData\Local\obfs4proxy.exe") is True

    def test_does_not_match_unrelated_program(self):
        assert is_tor_related(r"C:\Windows\System32\notepad.exe") is False

    def test_does_not_match_bare_firefox_outside_tor_dir(self):
        # Vanilla Firefox must not be flagged just because the basename is
        # firefox.exe — only Tor Browser's install-path-qualified firefox.exe
        # should match (see constants.py docstring on recall vs. precision).
        assert is_tor_related(r"C:\Program Files\Mozilla Firefox\firefox.exe") is False

    def test_none_and_empty_are_not_related(self):
        assert is_tor_related(None) is False
        assert is_tor_related("") is False

    def test_matches_tor_project_domain_marker(self):
        assert is_tor_related(r"C:\Users\bob\Downloads\torbrowser-install-win64.exe") is True


class TestCandidatePath:
    def test_user_assist_uses_name_field(self):
        entry = {"name": r"C:\Tor Browser\Browser\firefox.exe", "run_counter": 3}
        assert (
            candidate_path(ARTIFACT_TYPE_USER_ASSIST, entry)
            == r"C:\Tor Browser\Browser\firefox.exe"
        )

    def test_amcache_falls_back_across_field_names(self):
        entry = {"lower_case_long_path": r"c:\tor browser\browser\firefox.exe"}
        assert candidate_path(ARTIFACT_TYPE_AMCACHE, entry) == r"c:\tor browser\browser\firefox.exe"

    def test_missing_field_returns_none(self):
        assert candidate_path(ARTIFACT_TYPE_SHIMCACHE, {}) is None


# ---------------------------------------------------------------------------
# normalize_entry() — pure, no file I/O
# ---------------------------------------------------------------------------


class TestNormalizeEntry:
    def test_user_assist_is_high_confidence(self):
        entry = {
            "name": r"C:\Tor Browser\Browser\firefox.exe",
            "timestamp": "2026-07-14T14:15:22+00:00",
            "run_counter": 14,
            "focus_count": 20,
            "total_focus_time_ms": 500000,
        }
        artifact = normalize_entry(ARTIFACT_TYPE_USER_ASSIST, entry, "NTUSER.DAT")

        assert isinstance(artifact, Artifact)
        assert artifact.module == "module_a_registry"
        assert artifact.artifact_type == ARTIFACT_TYPE_USER_ASSIST
        assert artifact.source == "NTUSER.DAT"
        assert artifact.timestamp == "2026-07-14T14:15:22+00:00"
        assert "HIGH" in artifact.description
        assert "run_count=14" in artifact.description

    def test_shimcache_is_medium_confidence_and_says_not_confirmed_execution(self):
        entry = {
            "path": r"C:\Tor Browser\Browser\firefox.exe",
            "last_mod_date": "2026-07-14T00:00:00+00:00",
        }
        artifact = normalize_entry(ARTIFACT_TYPE_SHIMCACHE, entry, "SYSTEM")

        assert "MEDIUM" in artifact.description
        assert "not confirmed execution" in artifact.description

    def test_amcache_is_high_confidence_and_includes_sha1(self):
        entry = {
            "full_path": r"C:\Tor Browser\Browser\firefox.exe",
            "timestamp": "2026-07-10T09:01:47+00:00",
            "sha1": "b3f2e91a",
            "size": 123456,
        }
        artifact = normalize_entry(ARTIFACT_TYPE_AMCACHE, entry, "Amcache.hve")

        assert "HIGH" in artifact.description
        assert "sha1=b3f2e91a" in artifact.description
        assert artifact.timestamp == "2026-07-10T09:01:47+00:00"

    def test_recentdocs_is_low_confidence(self):
        entry = {
            "name": "secret-notes.txt",
            "extension": ".txt",
            "last_write": "2026-07-11T00:00:00+00:00",
        }
        artifact = normalize_entry(ARTIFACT_TYPE_RECENTDOCS, entry, "NTUSER.DAT")

        assert "LOW" in artifact.description
        assert "corroborating evidence only" in artifact.description

    def test_unknown_artifact_type_raises(self):
        with pytest.raises(ValueError):
            normalize_entry("NotARealType", {}, "NTUSER.DAT")


# ---------------------------------------------------------------------------
# Pipeline: integrity + repeatability, with extractors mocked out.
# ---------------------------------------------------------------------------

_MOCK_USER_ASSIST_ENTRIES = [
    {
        "name": r"C:\Users\bob\Desktop\Tor Browser\Browser\firefox.exe",
        "timestamp": "2026-07-14T14:15:22+00:00",
        "run_counter": 14,
        "focus_count": 20,
        "total_focus_time_ms": 500000,
    },
    {
        "name": r"C:\Windows\System32\notepad.exe",
        "timestamp": "2026-07-12T10:00:00+00:00",
        "run_counter": 2,
        "focus_count": 2,
        "total_focus_time_ms": 1000,
    },
]

_MOCK_RECENTDOCS_ENTRIES: list[dict] = []

_MOCK_SHIMCACHE_ENTRIES = [
    {
        "path": r"C:\Users\bob\Desktop\Tor Browser\Browser\firefox.exe",
        "last_mod_date": "2026-07-14T00:00:00+00:00",
    },
]

_MOCK_AMCACHE_ENTRIES = [
    {
        "full_path": r"C:\Users\bob\Desktop\Tor Browser\Browser\firefox.exe",
        "timestamp": "2026-07-10T09:01:47+00:00",
        "sha1": "b3f2e91a",
        "size": 123456,
    },
]


def _patch_extractors():
    """Patch every extractor at its point of use inside pipeline.py."""
    return (
        patch(
            "modules.module_a_registry.pipeline.extract_user_assist",
            return_value=_MOCK_USER_ASSIST_ENTRIES,
        ),
        patch(
            "modules.module_a_registry.pipeline.extract_recentdocs",
            return_value=_MOCK_RECENTDOCS_ENTRIES,
        ),
        patch(
            "modules.module_a_registry.pipeline.extract_shimcache",
            return_value=_MOCK_SHIMCACHE_ENTRIES,
        ),
        patch(
            "modules.module_a_registry.pipeline.extract_amcache", return_value=_MOCK_AMCACHE_ENTRIES
        ),
    )


def _run_pipeline_with_mocks(tmp_path: Path, output_dir: Path):
    tmp_path.mkdir(parents=True, exist_ok=True)
    ntuser = tmp_path / "NTUSER.DAT"
    system = tmp_path / "SYSTEM"
    amcache = tmp_path / "Amcache.hve"
    for f in (ntuser, system, amcache):
        f.write_bytes(b"synthetic-fixture-hive-content-not-a-real-hive")

    config = TranceConfig(case_name="test-case", output_dir=output_dir)

    patchers = _patch_extractors()
    for p in patchers:
        p.start()
    try:
        result = run_module_a(config, ntuser=ntuser, system=system, amcache=amcache)
    finally:
        for p in patchers:
            p.stop()

    return result


class TestPipelineIntegrity:
    def test_pre_and_post_parse_hashes_match_in_custody_log(self, tmp_path):
        output_dir = tmp_path / "out"
        result = _run_pipeline_with_mocks(tmp_path, output_dir)

        custody_log_path = Path(result.custody_log_path)
        assert custody_log_path.exists()

        entries = json.loads(custody_log_path.read_text())
        by_path: dict[str, list[dict]] = {}
        for entry in entries:
            by_path.setdefault(entry["artifact_path"], []).append(entry)

        assert len(by_path) == 3  # ntuser, system, amcache
        for path, hive_entries in by_path.items():
            actions = {e["action"]: e["sha256"] for e in hive_entries}
            assert "ingest_pre_parse" in actions
            assert "post_parse_verify" in actions
            assert (
                actions["ingest_pre_parse"] == actions["post_parse_verify"]
            ), f"Hash changed across parsing for {path} — read-only violation."

    def test_only_tor_related_entries_survive_filtering(self, tmp_path):
        output_dir = tmp_path / "out"
        result = _run_pipeline_with_mocks(tmp_path, output_dir)

        # notepad.exe (non-Tor) must be filtered out; firefox.exe under
        # Tor Browser must survive, across all three artifact types provided.
        assert len(result.findings) == 3
        artifact_types = {f.artifact_type for f in result.findings}
        assert artifact_types == {
            ARTIFACT_TYPE_USER_ASSIST,
            ARTIFACT_TYPE_SHIMCACHE,
            ARTIFACT_TYPE_AMCACHE,
        }
        assert all("notepad" not in f.description.lower() for f in result.findings)

    def test_integrity_error_raised_on_hash_mismatch(self, tmp_path):
        ntuser = tmp_path / "NTUSER.DAT"
        ntuser.write_bytes(b"original-content")
        output_dir = tmp_path / "out"
        config = TranceConfig(case_name="test-case", output_dir=output_dir)

        def _mutating_extract_user_assist(path):
            # Simulate a (forbidden) write to the source hive during parsing.
            Path(path).write_bytes(b"mutated-content")
            return []

        with (
            patch(
                "modules.module_a_registry.pipeline.extract_user_assist",
                side_effect=_mutating_extract_user_assist,
            ),
            patch("modules.module_a_registry.pipeline.extract_recentdocs", return_value=[]),
            pytest.raises(IntegrityError),
        ):
            run_module_a(config, ntuser=ntuser)

    def test_missing_hives_do_not_raise_and_are_noted_in_summary(self, tmp_path):
        output_dir = tmp_path / "out"
        config = TranceConfig(case_name="test-case", output_dir=output_dir)

        result = run_module_a(config)  # no hives at all

        assert result.findings == []
        assert "not provided" in result.summary
        assert "NTUSER.DAT" in result.summary
        assert "SYSTEM" in result.summary
        assert "Amcache.hve" in result.summary

    def test_extraction_error_is_recorded_not_raised(self, tmp_path):
        ntuser = tmp_path / "NTUSER.DAT"
        ntuser.write_bytes(b"synthetic")
        output_dir = tmp_path / "out"
        config = TranceConfig(case_name="test-case", output_dir=output_dir)

        with (
            patch(
                "modules.module_a_registry.pipeline.extract_user_assist",
                side_effect=ParsingError("boom"),
            ),
            patch("modules.module_a_registry.pipeline.extract_recentdocs", return_value=[]),
        ):
            result = run_module_a(config, ntuser=ntuser)

        assert any("boom" in e for e in result.errors)


class TestPipelineRepeatability:
    def test_two_runs_produce_byte_identical_output(self, tmp_path):
        # Same input hive paths for both runs — only the output directory
        # differs — so Artifact.source is identical across runs and this
        # actually isolates repeatability of the pipeline's own logic
        # rather than an artifact of using different temp paths per run.
        hives_dir = tmp_path / "hives"
        output_dir_1 = tmp_path / "run1"
        output_dir_2 = tmp_path / "run2"

        result_1 = _run_pipeline_with_mocks(hives_dir, output_dir_1)
        result_2 = _run_pipeline_with_mocks(hives_dir, output_dir_2)

        out_1 = write_output(result_1, output_dir_1 / "module_a_registry.json")
        out_2 = write_output(result_2, output_dir_2 / "module_a_registry.json")

        assert out_1.read_bytes() == out_2.read_bytes()

    def test_output_matches_expected_schema(self, tmp_path):
        output_dir = tmp_path / "out"
        result = _run_pipeline_with_mocks(tmp_path, output_dir)
        out_path = write_output(result, output_dir / "module_a_registry.json")

        payload = json.loads(out_path.read_text())
        assert payload["module"] == "module_a_registry"
        assert isinstance(payload["findings"], list)
        assert isinstance(payload["summary"], str)
        assert "installed" in payload["summary"]
        assert "executed" in payload["summary"]
