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
    ARTIFACT_TYPE_BAM,
    ARTIFACT_TYPE_COMDLG32,
    ARTIFACT_TYPE_INSTALLEDPROGRAMS,
    ARTIFACT_TYPE_MUICACHE,
    ARTIFACT_TYPE_RECENTDOCS,
    ARTIFACT_TYPE_RUNMRU,
    ARTIFACT_TYPE_SHIMCACHE,
    ARTIFACT_TYPE_USER_ASSIST,
    ARTIFACT_TYPE_WORDWHEELQUERY,
    candidate_path,
    harddiskvolume_number,
    infer_drive_letters,
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


class TestInferDriveLetters:
    """\\Device\\HarddiskVolumeN -> drive letter, inferred from the SAME evidence set --
    see constants.infer_drive_letters' docstring for why MountedDevices can't answer
    this (it maps letters to volume GUIDs/disk signatures, never to the HarddiskVolumeN
    ordinal) and same-evidence correlation is used instead."""

    def test_unambiguous_match_is_inferred(self):
        paths = {
            r"\Device\HarddiskVolume6\Tor Browser\Browser\firefox.exe",
            r"E:\Tor Browser\Browser\firefox.exe",
        }
        assert infer_drive_letters(paths) == {
            r"\Device\HarddiskVolume6\Tor Browser\Browser\firefox.exe": "E"
        }

    def test_no_matching_drive_letter_path_is_left_unresolved(self):
        paths = {r"\Device\HarddiskVolume6\Tor Browser\Browser\firefox.exe"}
        assert infer_drive_letters(paths) == {}

    def test_ambiguous_match_across_two_drive_letters_is_left_unresolved(self):
        # Two different drives both happen to hold a file at the same relative path --
        # genuinely ambiguous, must not guess either one.
        paths = {
            r"\Device\HarddiskVolume6\Tor Browser\Browser\firefox.exe",
            r"E:\Tor Browser\Browser\firefox.exe",
            r"F:\Tor Browser\Browser\firefox.exe",
        }
        assert infer_drive_letters(paths) == {}

    def test_case_insensitive_suffix_match(self):
        paths = {
            r"\device\harddiskvolume6\Tor Browser\Browser\firefox.exe",
            r"e:\TOR BROWSER\Browser\firefox.exe",
        }
        resolved = infer_drive_letters(paths)
        assert resolved == {r"\device\harddiskvolume6\Tor Browser\Browser\firefox.exe": "E"}

    def test_harddiskvolume_number_extracts_the_ordinal(self):
        assert harddiskvolume_number(r"\Device\HarddiskVolume6\Tor Browser\firefox.exe") == "6"
        assert harddiskvolume_number(r"E:\Tor Browser\firefox.exe") is None
        assert harddiskvolume_number(None) is None


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

    def test_bam_uses_executable_field(self):
        entry = {"executable": r"C:\Tor Browser\Browser\firefox.exe"}
        assert candidate_path(ARTIFACT_TYPE_BAM, entry) == r"C:\Tor Browser\Browser\firefox.exe"
        assert is_tor_related(candidate_path(ARTIFACT_TYPE_BAM, entry)) is True
        assert (
            is_tor_related(
                candidate_path(
                    ARTIFACT_TYPE_BAM, {"executable": r"C:\Windows\System32\notepad.exe"}
                )
            )
            is False
        )

    def test_installed_programs_falls_back_across_field_names(self):
        entry = {"InstallLocation": r"C:\Tor Browser"}
        assert candidate_path(ARTIFACT_TYPE_INSTALLEDPROGRAMS, entry) == r"C:\Tor Browser"
        assert (
            candidate_path(ARTIFACT_TYPE_INSTALLEDPROGRAMS, {"DisplayName": "Tor Browser"})
            == "Tor Browser"
        )


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

    def test_bam_is_high_confidence_and_includes_sid(self):
        entry = {
            "executable": r"\Device\HarddiskVolume3\Tor Browser\Browser\firefox.exe",
            "timestamp": "2026-07-14T14:15:22+00:00",
            "sid": "S-1-5-21-1-2-3-1001",
        }
        artifact = normalize_entry(ARTIFACT_TYPE_BAM, entry, "SYSTEM")

        assert "HIGH" in artifact.description
        assert "sid=S-1-5-21-1-2-3-1001" in artifact.description
        assert artifact.timestamp == "2026-07-14T14:15:22+00:00"

    def test_muicache_is_medium_confidence(self):
        entry = {
            "path": r"C:\Tor Browser\Browser\firefox.exe",
            "display_name": "Tor Browser",
            "last_write": "2026-07-14T00:00:00+00:00",
        }
        artifact = normalize_entry(ARTIFACT_TYPE_MUICACHE, entry, "NTUSER.DAT")

        assert "MEDIUM" in artifact.description
        assert "not confirmed execution" in artifact.description

    def test_runmru_is_low_confidence(self):
        entry = {
            "command": r"C:\Tor Browser\Browser\firefox.exe",
            "last_write": "2026-07-14T00:00:00+00:00",
        }
        artifact = normalize_entry(ARTIFACT_TYPE_RUNMRU, entry, "NTUSER.DAT")

        assert "LOW" in artifact.description
        assert "for 'C:\\Tor Browser\\Browser\\firefox.exe'" in artifact.description

    def test_word_wheel_query_is_low_confidence(self):
        entry = {"name": "tor browser", "last_write": "2026-07-14T00:00:00+00:00"}
        artifact = normalize_entry(ARTIFACT_TYPE_WORDWHEELQUERY, entry, "NTUSER.DAT")

        assert "LOW" in artifact.description
        assert "for 'tor browser'" in artifact.description

    def test_comdlg32_is_low_confidence(self):
        entry = {
            "path": r"C:\Tor Browser\Browser\firefox.exe",
            "mru_type": "OpenSavePidlMRU",
            "last_write": "2026-07-14T00:00:00+00:00",
        }
        artifact = normalize_entry(ARTIFACT_TYPE_COMDLG32, entry, "NTUSER.DAT")

        assert "LOW" in artifact.description
        assert "for 'C:\\Tor Browser\\Browser\\firefox.exe'" in artifact.description

    def test_installed_programs_is_high_confidence_and_includes_install_date(self):
        entry = {
            "DisplayName": "Tor Browser",
            "Publisher": "The Tor Project",
            "InstallDate": "20260714",
            "timestamp": "2026-07-14T00:00:00+00:00",
        }
        artifact = normalize_entry(ARTIFACT_TYPE_INSTALLEDPROGRAMS, entry, "SOFTWARE")

        assert "HIGH" in artifact.description
        assert "InstallDate=20260714" in artifact.description
        assert artifact.timestamp == "2026-07-14T00:00:00+00:00"

    def test_unknown_artifact_type_raises(self):
        with pytest.raises(ValueError):
            normalize_entry("NotARealType", {}, "NTUSER.DAT")

    def test_null_filetime_timestamp_becomes_none(self):
        # A raw FILETIME of 0 (field never set) decodes to exactly the Windows FILETIME
        # epoch -- a real date string, not an error, so nothing upstream would catch it.
        entry = {
            "name": r"C:\Tor Browser\Browser\firefox.exe",
            "timestamp": "1601-01-01T00:00:00+00:00",
            "run_counter": 0,
        }
        artifact = normalize_entry(ARTIFACT_TYPE_USER_ASSIST, entry, "NTUSER.DAT")

        assert artifact.timestamp is None

    def test_real_timestamp_near_but_not_at_filetime_epoch_is_kept(self):
        entry = {
            "name": r"C:\Tor Browser\Browser\firefox.exe",
            "timestamp": "1601-01-02T00:00:00+00:00",
            "run_counter": 1,
        }
        artifact = normalize_entry(ARTIFACT_TYPE_USER_ASSIST, entry, "NTUSER.DAT")

        assert artifact.timestamp == "1601-01-02T00:00:00+00:00"


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


# ---------------------------------------------------------------------------
# Real bug: summary said "executed 4 times" when the table showed one launch.
# Root cause was two stacked problems in _update_stats()'s run_counter sum:
# regipy returning each real entry twice, and a .lnk shortcut + the firefox.exe
# it starts sharing one timestamp (one user action, counted as two). See
# pipeline.py's _update_stats()/_build_summary() docstrings.
# ---------------------------------------------------------------------------

_DUPLICATED_LINKED_LAUNCH_ENTRIES = [
    # firefox.exe, reported twice by regipy (identical entry) -- the same real launch.
    {
        "name": r"E:\Tor Browser\Browser\firefox.exe",
        "timestamp": "2026-09-03T04:41:53.211000+00:00",
        "run_counter": 1,
    },
    {
        "name": r"E:\Tor Browser\Browser\firefox.exe",
        "timestamp": "2026-09-03T04:41:53.211000+00:00",
        "run_counter": 1,
    },
    # Tor Browser.lnk, also reported twice -- same exact timestamp as firefox.exe above:
    # one user action (click the shortcut, which starts firefox.exe), two UserAssist GUIDs.
    {
        "name": r"E:\Tor Browser\Tor Browser.lnk",
        "timestamp": "2026-09-03T04:41:53.211000+00:00",
        "run_counter": 1,
    },
    {
        "name": r"E:\Tor Browser\Tor Browser.lnk",
        "timestamp": "2026-09-03T04:41:53.211000+00:00",
        "run_counter": 1,
    },
    # The installer: never actually launched (run_counter=0), null/epoch-zero timestamp --
    # must not count as a launch at all.
    {
        "name": (
            r"C:\Users\Admin\AppData\Local\Temp\MicrosoftEdgeDownloads\g\\"
            r"tor-browser-windows-x86_64-portable-15.0.21.exe"
        ),
        "timestamp": "1601-01-01T00:00:00+00:00",
        "run_counter": 0,
    },
    {
        "name": (
            r"C:\Users\Admin\AppData\Local\Temp\MicrosoftEdgeDownloads\g\\"
            r"tor-browser-windows-x86_64-portable-15.0.21.exe"
        ),
        "timestamp": "1601-01-01T00:00:00+00:00",
        "run_counter": 0,
    },
]


class TestLaunchCounting:
    def test_duplicates_and_linked_launch_count_as_one_launch(self, tmp_path):
        ntuser = tmp_path / "NTUSER.DAT"
        ntuser.write_bytes(b"synthetic")
        output_dir = tmp_path / "out"
        config = TranceConfig(case_name="test-case", output_dir=output_dir)

        with (
            patch(
                "modules.module_a_registry.pipeline.extract_user_assist",
                return_value=_DUPLICATED_LINKED_LAUNCH_ENTRIES,
            ),
            patch("modules.module_a_registry.pipeline.extract_recentdocs", return_value=[]),
        ):
            result = run_module_a(config, ntuser=ntuser)

        assert "launched 1 time" in result.summary
        assert "launched 1 times" not in result.summary  # pluralization
        assert "launched 2 times" not in result.summary
        assert "launched 4 times" not in result.summary
        assert "executed" not in result.summary

    def test_distinct_timestamps_each_count_as_a_separate_launch(self, tmp_path):
        entries = [
            {
                "name": r"E:\Tor Browser\Browser\firefox.exe",
                "timestamp": "2026-09-03T04:41:53+00:00",
                "run_counter": 1,
            },
            {
                "name": r"E:\Tor Browser\Browser\firefox.exe",
                "timestamp": "2026-09-05T10:00:00+00:00",
                "run_counter": 2,
            },
        ]
        ntuser = tmp_path / "NTUSER.DAT"
        ntuser.write_bytes(b"synthetic")
        output_dir = tmp_path / "out"
        config = TranceConfig(case_name="test-case", output_dir=output_dir)

        with (
            patch("modules.module_a_registry.pipeline.extract_user_assist", return_value=entries),
            patch("modules.module_a_registry.pipeline.extract_recentdocs", return_value=[]),
        ):
            result = run_module_a(config, ntuser=ntuser)

        assert "launched 2 times" in result.summary


class TestSoftwareHiveIsOptional:
    def test_runs_without_software_same_as_other_optional_hives(self, tmp_path):
        """SOFTWARE is a fourth optional hive, same degrade-gracefully contract as
        ntuser/system/amcache -- omitting it must not affect the other three."""
        ntuser = tmp_path / "NTUSER.DAT"
        ntuser.write_bytes(b"synthetic")
        output_dir = tmp_path / "out"
        config = TranceConfig(case_name="test-case", output_dir=output_dir)

        with (
            patch(
                "modules.module_a_registry.pipeline.extract_user_assist",
                return_value=[
                    {
                        "name": r"E:\Tor Browser\Browser\firefox.exe",
                        "timestamp": "2026-07-14T14:15:22+00:00",
                        "run_counter": 1,
                    }
                ],
            ),
            patch("modules.module_a_registry.pipeline.extract_recentdocs", return_value=[]),
        ):
            result = run_module_a(config, ntuser=ntuser)

        assert len(result.findings) == 1
        assert result.profiles == []
        assert "launched 1 time" in result.summary

    def test_software_hive_populates_installed_programs_and_profiles(self, tmp_path):
        ntuser = tmp_path / "NTUSER.DAT"
        software = tmp_path / "SOFTWARE"
        for f in (ntuser, software):
            f.write_bytes(b"synthetic")
        output_dir = tmp_path / "out"
        config = TranceConfig(case_name="test-case", output_dir=output_dir)

        profiles = [{"path": r"C:\Users\Admin", "sid": "S-1-5-21-1-2-3-1001", "last_write": None}]
        installed = [
            {
                "DisplayName": "Tor Browser",
                "timestamp": "2026-07-14T00:00:00+00:00",
                "registry_path": r"Microsoft\Windows\CurrentVersion\Uninstall",
            },
            {
                "DisplayName": "Totally Unrelated App",
                "timestamp": "2026-07-14T00:00:00+00:00",
                "registry_path": r"Microsoft\Windows\CurrentVersion\Uninstall",
            },
        ]

        with (
            patch("modules.module_a_registry.pipeline.extract_user_assist", return_value=[]),
            patch("modules.module_a_registry.pipeline.extract_recentdocs", return_value=[]),
            patch(
                "modules.module_a_registry.pipeline.extract_installed_programs",
                return_value=installed,
            ),
            patch("modules.module_a_registry.pipeline.extract_profiles", return_value=profiles),
        ):
            result = run_module_a(config, ntuser=ntuser, software=software)

        assert len(result.findings) == 1  # only the Tor-related install, not the unrelated app
        assert result.findings[0].artifact_type == ARTIFACT_TYPE_INSTALLEDPROGRAMS
        assert result.profiles == profiles


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

    def test_summary_timestamps_are_human_readable_not_raw_isoformat(self, tmp_path):
        output_dir = tmp_path / "out"
        result = _run_pipeline_with_mocks(tmp_path, output_dir)

        # Amcache mock timestamp is "2026-07-10T09:01:47+00:00" (install), UserAssist
        # mock's later timestamp is "2026-07-14T14:15:22+00:00" (last run) -- both
        # should read as "YYYY-MM-DD HH:MM:SS UTC", not the raw ISO +00:00 offset.
        assert "2026-07-10 09:01:47 UTC" in result.summary
        assert "2026-07-14 14:15:22 UTC" in result.summary
        assert "+00:00" not in result.summary

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
        assert "launched" in payload["summary"]
