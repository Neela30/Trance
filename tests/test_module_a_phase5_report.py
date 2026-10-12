"""Tests for Phase 5 of the Module A roadmap -- report integration: "Automatic start and
proxy settings", "Files involved", the portable-install InstalledPrograms note, and the
glossary additions."""

from __future__ import annotations

from modules.module_a_registry.narrative import (
    GLOSSARY,
    build_autostart_narrative,
    describe_not_determined,
    describe_portable_install_note,
    describe_proxy_configuration,
    describe_run_key_autostart,
    describe_service_autostart,
)
from modules.module_a_registry.report import (
    _build_autostart_context,
    _build_files_involved,
    _quiet_hive_notes,
)


class TestAutostartNarrative:
    def test_run_key_sentence_names_path_and_value_name(self):
        sentences = describe_run_key_autostart(
            [{"path": r"E:\Tor Browser\Browser\firefox.exe", "value_name": "Tor Autostart"}]
        )
        assert len(sentences) == 1
        assert r"E:\Tor Browser\Browser\firefox.exe" in sentences[0]
        assert "Tor Autostart" in sentences[0]
        assert "automatically" in sentences[0]

    def test_service_sentence_names_path_and_service_name(self):
        sentences = describe_service_autostart([{"path": r"C:\Tor\tor.exe", "service_name": "tor"}])
        assert len(sentences) == 1
        assert r"C:\Tor\tor.exe" in sentences[0]
        assert "'tor'" in sentences[0]

    def test_proxy_sentence_names_server(self):
        sentences = describe_proxy_configuration([{"proxy_server": "127.0.0.1:9050"}])
        assert len(sentences) == 1
        assert "127.0.0.1:9050" in sentences[0]

    def test_build_autostart_narrative_empty_when_nothing_found(self):
        assert build_autostart_narrative([], [], []) == []

    def test_build_autostart_narrative_combines_all_three(self):
        sentences = build_autostart_narrative(
            [{"path": r"E:\Tor\firefox.exe", "value_name": "X"}],
            [{"path": r"C:\Tor\tor.exe", "service_name": "tor"}],
            [{"proxy_server": "127.0.0.1:9050"}],
        )
        assert len(sentences) == 3


class TestPortableInstallNote:
    def test_none_when_installed_programs_present(self):
        assert describe_portable_install_note(True) is None

    def test_note_when_installed_programs_absent(self):
        note = describe_portable_install_note(False)
        assert note is not None
        assert "portable" in note
        assert "expected" in note


class TestBuildAutostartContext:
    def test_empty_annotated_by_type(self):
        ctx = _build_autostart_context({})
        assert ctx["run_keys"] == []
        assert ctx["services"] == []
        assert ctx["proxy_settings"] == []
        assert ctx["narrative"] == []

    def test_populated(self):
        annotated = {
            "RunKey": [{"path": r"E:\Tor\firefox.exe", "value_name": "X"}],
            "Service": [{"path": r"C:\Tor\tor.exe", "service_name": "tor"}],
            "ProxySettings": [{"proxy_server": "127.0.0.1:9050"}],
        }
        ctx = _build_autostart_context(annotated)
        assert len(ctx["run_keys"]) == 1
        assert len(ctx["services"]) == 1
        assert len(ctx["proxy_settings"]) == 1
        assert len(ctx["narrative"]) == 3


class TestBuildFilesInvolved:
    def test_merges_and_sorts_by_timestamp(self):
        annotated = {
            "ComDlg32": [
                {"path": r"E:\Downloads\file1.txt", "timestamp": "2026-01-03T00:00:00+00:00"}
            ],
            "RecentDocs": [
                {"path": r"E:\Downloads\file2.txt", "timestamp": "2026-01-01T00:00:00+00:00"}
            ],
            "ShellBags": [{"path": r"E:\Downloads", "timestamp": "2026-01-02T00:00:00+00:00"}],
        }
        files = _build_files_involved(annotated)
        assert [f["source"] for f in files] == ["RecentDocs", "ShellBags", "ComDlg32"]

    def test_findings_without_path_are_skipped(self):
        annotated = {"ComDlg32": [{"path": None, "timestamp": "2026-01-01T00:00:00+00:00"}]}
        assert _build_files_involved(annotated) == []

    def test_empty_when_no_relevant_types_present(self):
        assert _build_files_involved({"UserAssist": [{"path": "x", "timestamp": None}]}) == []


class TestQuietHiveNotesPortableInstall:
    def test_note_added_when_software_provided_and_no_installed_programs(self):
        notes = _quiet_hive_notes({"software": True}, {})
        assert any("portable" in n for n in notes)

    def test_note_absent_when_installed_programs_present(self):
        notes = _quiet_hive_notes({"software": True}, {"InstalledPrograms": [{"x": 1}]})
        assert not any("portable" in n for n in notes)

    def test_note_absent_when_software_not_provided(self):
        notes = _quiet_hive_notes({"software": False}, {})
        assert not any("portable" in n for n in notes)


class TestNotDeterminedNetworkBullet:
    def test_omitted_by_default(self):
        bullets = describe_not_determined(None, multiple_launches=False)
        assert not any("network" in b.lower() for b in bullets)

    def test_included_when_network_profiles_present(self):
        bullets = describe_not_determined(None, multiple_launches=False, has_network_profiles=True)
        assert any("exact moment Tor Browser was opened" in b for b in bullets)


class TestGlossaryAdditions:
    def test_phase3_4_5_terms_present(self):
        for term in (
            "NetworkList",
            "SSID",
            "gateway MAC address",
            "DHCP lease",
            "Run key",
            "service",
            "proxy",
            "SOCKS port",
        ):
            assert term in GLOSSARY
            assert GLOSSARY[term]
