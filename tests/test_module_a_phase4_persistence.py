"""Tests for Phase 4 of the Module A roadmap -- persistence and configuration (Run/
RunOnce, Windows services, Internet Settings proxy configuration).

RegistryHive is mocked throughout, per this project's "never touch real evidence" rule.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from regipy.exceptions import RegistryKeyNotFoundException

from modules.module_a_registry.custom_extractors import (
    extract_proxy_settings,
    extract_run_keys_ntuser,
    extract_run_keys_software,
    extract_services,
)
from modules.module_a_registry.normalize import normalize_entry
from modules.module_a_registry.report import _annotate


def _fake_value(name: str, value) -> MagicMock:
    v = MagicMock()
    v.name = name
    v.value = value
    return v


def _fake_key(values: list, last_modified: int = 0) -> MagicMock:
    key = MagicMock()
    key.iter_values.return_value = values
    key.header.last_modified = last_modified
    return key


def _fake_service_subkey(name: str, values: dict, last_modified: int = 0) -> MagicMock:
    subkey = MagicMock()
    subkey.name = name
    subkey.header.last_modified = last_modified
    subkey.get_value.side_effect = lambda value_name: values.get(value_name)
    return subkey


class TestExtractRunKeysNtuser:
    def test_reads_run_and_runonce(self, tmp_path):
        ntuser_path = tmp_path / "NTUSER.DAT"
        ntuser_path.write_bytes(b"synthetic")

        run_key = _fake_key(
            [_fake_value("Tor Autostart", r'"E:\Tor Browser\Browser\firefox.exe" -profile X')]
        )
        runonce_key = _fake_key([])

        def get_key(path):
            if path.endswith("\\Run"):
                return run_key
            if path.endswith("\\RunOnce"):
                return runonce_key
            raise RegistryKeyNotFoundException(path)

        fake_hive = MagicMock()
        fake_hive.get_key.side_effect = get_key

        with patch(
            "modules.module_a_registry.custom_extractors.RegistryHive", return_value=fake_hive
        ):
            result = extract_run_keys_ntuser(ntuser_path)

        assert len(result) == 1
        assert result[0]["name"] == "Tor Autostart"
        assert result[0]["executable"] == r"E:\Tor Browser\Browser\firefox.exe"

    def test_both_keys_missing_returns_empty(self, tmp_path):
        ntuser_path = tmp_path / "NTUSER.DAT"
        ntuser_path.write_bytes(b"synthetic")

        fake_hive = MagicMock()
        fake_hive.get_key.side_effect = RegistryKeyNotFoundException("missing")

        with patch(
            "modules.module_a_registry.custom_extractors.RegistryHive", return_value=fake_hive
        ):
            result = extract_run_keys_ntuser(ntuser_path)

        assert result == []

    def test_unrelated_entries_pass_through_unfiltered(self, tmp_path):
        """Extraction itself does no filtering (consistent with every other extractor) --
        Chrome/Docker/Teams-shaped entries are returned raw; is_tor_related_entry() in
        pipeline.py is the only gate."""
        ntuser_path = tmp_path / "NTUSER.DAT"
        ntuser_path.write_bytes(b"synthetic")

        run_key = _fake_key(
            [_fake_value("GoogleChromeAutoLaunch", '"C:\\Chrome\\chrome.exe" --no-startup-window')]
        )
        fake_hive = MagicMock()
        fake_hive.get_key.side_effect = lambda path: (
            run_key
            if path.endswith("\\Run")
            else (_ for _ in ()).throw(RegistryKeyNotFoundException(path))
        )

        with patch(
            "modules.module_a_registry.custom_extractors.RegistryHive", return_value=fake_hive
        ):
            result = extract_run_keys_ntuser(ntuser_path)

        assert len(result) == 1
        assert result[0]["executable"] == "C:\\Chrome\\chrome.exe"


class TestExtractRunKeysSoftware:
    def test_reads_all_four_paths(self, tmp_path):
        software_path = tmp_path / "SOFTWARE"
        software_path.write_bytes(b"synthetic")

        run_key = _fake_key([_fake_value("SecurityHealth", "%windir%\\SecurityHealthSystray.exe")])
        wow_run_key = _fake_key([_fake_value("TorService32", r"C:\Tor32\tor.exe")])

        def get_key(path):
            if path == r"\Microsoft\Windows\CurrentVersion\Run":
                return run_key
            if path == r"\WOW6432Node\Microsoft\Windows\CurrentVersion\Run":
                return wow_run_key
            raise RegistryKeyNotFoundException(path)

        fake_hive = MagicMock()
        fake_hive.get_key.side_effect = get_key

        with patch(
            "modules.module_a_registry.custom_extractors.RegistryHive", return_value=fake_hive
        ):
            result = extract_run_keys_software(software_path)

        assert len(result) == 2
        names = {r["name"] for r in result}
        assert names == {"SecurityHealth", "TorService32"}


class TestExtractServices:
    def test_tor_exe_image_path_matches(self, tmp_path):
        system_path = tmp_path / "SYSTEM"
        system_path.write_bytes(b"synthetic")

        tor_service = _fake_service_subkey(
            "tor",
            {
                "ImagePath": r'"C:\Tor\tor.exe" --service',
                "DisplayName": "Tor Win32 Service",
                "Start": 2,
                "ObjectName": "LocalSystem",
            },
        )
        other_service = _fake_service_subkey(
            "RtkAudUService",
            {"ImagePath": r'"C:\RtkAudUService64.exe" -background'},
        )
        services_key = MagicMock()
        services_key.iter_subkeys.return_value = [tor_service, other_service]

        fake_hive = MagicMock()
        fake_hive.get_control_sets.return_value = [r"\ControlSet001\Services"]
        fake_hive.get_key.return_value = services_key

        with patch(
            "modules.module_a_registry.custom_extractors.RegistryHive", return_value=fake_hive
        ):
            result = extract_services(system_path)

        assert len(result) == 1
        assert result[0]["name"] == "tor"
        assert result[0]["executable"] == r"C:\Tor\tor.exe"
        assert result[0]["display_name"] == "Tor Win32 Service"
        assert result[0]["start"] == 2

    def test_service_named_tor_with_unrelated_wrapper_exe_still_matches(self, tmp_path):
        """nssm-wrapped Tor service: ImagePath points at nssm.exe, not tor.exe -- only the
        service's own name gives it away."""
        system_path = tmp_path / "SYSTEM"
        system_path.write_bytes(b"synthetic")

        tor_service = _fake_service_subkey("tor", {"ImagePath": r"C:\nssm\nssm.exe"})
        services_key = MagicMock()
        services_key.iter_subkeys.return_value = [tor_service]

        fake_hive = MagicMock()
        fake_hive.get_control_sets.return_value = [r"\ControlSet001\Services"]
        fake_hive.get_key.return_value = services_key

        with patch(
            "modules.module_a_registry.custom_extractors.RegistryHive", return_value=fake_hive
        ):
            result = extract_services(system_path)

        assert len(result) == 1
        assert result[0]["name"] == "tor"

    def test_no_tor_services_on_machine_returns_empty(self, tmp_path):
        """Confirmed against a real SYSTEM hive with 858 services and no Tor service --
        this is the overwhelmingly common case and must return cleanly, not list
        everything."""
        system_path = tmp_path / "SYSTEM"
        system_path.write_bytes(b"synthetic")

        ordinary_services = [
            _fake_service_subkey("storvsc", {"ImagePath": r"System32\drivers\storvsc.sys"}),
            _fake_service_subkey(
                "StorSvc", {"ImagePath": "%SystemRoot%\\System32\\svchost.exe -k Group"}
            ),
            _fake_service_subkey(
                "RpcLocator", {"ImagePath": "%systemroot%\\system32\\locator.exe"}
            ),
        ]
        services_key = MagicMock()
        services_key.iter_subkeys.return_value = ordinary_services

        fake_hive = MagicMock()
        fake_hive.get_control_sets.return_value = [r"\ControlSet001\Services"]
        fake_hive.get_key.return_value = services_key

        with patch(
            "modules.module_a_registry.custom_extractors.RegistryHive", return_value=fake_hive
        ):
            result = extract_services(system_path)

        # Regression guard for the naive-substring false-positive bug found during
        # planning: "storvsc"/"StorSvc"/"RpcLocator" all contain "tor" as a bare
        # substring (DriverStore, Locator) but must NOT match.
        assert result == []

    def test_missing_services_key_returns_empty(self, tmp_path):
        system_path = tmp_path / "SYSTEM"
        system_path.write_bytes(b"synthetic")

        fake_hive = MagicMock()
        fake_hive.get_control_sets.return_value = [r"\ControlSet001\Services"]
        fake_hive.get_key.side_effect = RegistryKeyNotFoundException("missing")

        with patch(
            "modules.module_a_registry.custom_extractors.RegistryHive", return_value=fake_hive
        ):
            result = extract_services(system_path)

        assert result == []


class TestExtractProxySettings:
    def test_reads_proxy_values(self, tmp_path):
        ntuser_path = tmp_path / "NTUSER.DAT"
        ntuser_path.write_bytes(b"synthetic")

        key = _fake_key([])
        key.get_value.side_effect = {
            "ProxyEnable": 1,
            "ProxyServer": "127.0.0.1:9050",
            "AutoConfigURL": None,
        }.get

        fake_hive = MagicMock()
        fake_hive.get_key.return_value = key

        with patch(
            "modules.module_a_registry.custom_extractors.RegistryHive", return_value=fake_hive
        ):
            result = extract_proxy_settings(ntuser_path)

        assert len(result) == 1
        assert result[0]["proxy_enable"] == 1
        assert result[0]["proxy_server"] == "127.0.0.1:9050"

    def test_missing_key_returns_empty_list(self, tmp_path):
        ntuser_path = tmp_path / "NTUSER.DAT"
        ntuser_path.write_bytes(b"synthetic")

        fake_hive = MagicMock()
        fake_hive.get_key.side_effect = RegistryKeyNotFoundException("missing")

        with patch(
            "modules.module_a_registry.custom_extractors.RegistryHive", return_value=fake_hive
        ):
            result = extract_proxy_settings(ntuser_path)

        assert result == []


class TestNormalizePersistence:
    def test_normalize_run_key(self):
        entry = {
            "key_path": r"\Software\Microsoft\Windows\CurrentVersion\Run",
            "name": "Tor Autostart",
            "command": r'"E:\Tor Browser\Browser\firefox.exe" -profile X',
            "executable": r"E:\Tor Browser\Browser\firefox.exe",
            "last_write": "2026-01-01T00:00:00+00:00",
        }
        artifact = normalize_entry("RunKey", entry, "NTUSER.DAT")
        assert artifact.category == "tor-direct"
        assert artifact.confidence == "high"
        assert r"E:\Tor Browser\Browser\firefox.exe" in artifact.description
        assert "Tor Autostart" in artifact.description

    def test_normalize_service(self):
        entry = {
            "name": "tor",
            "executable": r"C:\Tor\tor.exe",
            "start": 2,
            "last_write": "2026-01-01T00:00:00+00:00",
        }
        artifact = normalize_entry("Service", entry, "SYSTEM")
        assert "tor" in artifact.description
        assert r"C:\Tor\tor.exe" in artifact.description
        assert "start=2" in artifact.description

    def test_normalize_proxy_settings_enabled(self):
        entry = {
            "proxy_enable": 1,
            "proxy_server": "127.0.0.1:9050",
            "auto_config_url": None,
            "last_write": "2026-01-01T00:00:00+00:00",
        }
        artifact = normalize_entry("ProxySettings", entry, "NTUSER.DAT")
        assert "enabled=yes" in artifact.description
        assert "127.0.0.1:9050" in artifact.description

    def test_normalize_proxy_settings_disabled(self):
        entry = {"proxy_enable": 0, "proxy_server": "10.10.3.92:80"}
        artifact = normalize_entry("ProxySettings", entry, "NTUSER.DAT")
        assert "enabled=no" in artifact.description


class TestAnnotatePersistenceFields:
    def test_annotate_run_key_extracts_value_name_and_key_path(self):
        findings = [
            {
                "description": (
                    "RunKey entry 'E:\\Tor Browser\\Browser\\firefox.exe' "
                    "(value name='Tor Autostart', key=\\Software\\Microsoft\\Windows\\"
                    "CurrentVersion\\Run) — configured to start automatically."
                ),
            }
        ]
        annotated = _annotate(findings, "RunKey")
        assert annotated[0]["path"] == "E:\\Tor Browser\\Browser\\firefox.exe"
        assert annotated[0]["value_name"] == "Tor Autostart"
        assert "Run" in annotated[0]["key_path"]

    def test_annotate_service_extracts_name_and_start(self):
        findings = [
            {
                "description": (
                    "Service entry for 'C:\\Tor\\tor.exe' (service name='tor', start=2) "
                    "— installed as a Windows service."
                ),
            }
        ]
        annotated = _annotate(findings, "Service")
        assert annotated[0]["path"] == "C:\\Tor\\tor.exe"
        assert annotated[0]["service_name"] == "tor"
        assert annotated[0]["start"] == "2"

    def test_annotate_proxy_settings_extracts_fields(self):
        findings = [
            {
                "description": (
                    "Internet Settings proxy configuration (enabled=yes, "
                    "server=127.0.0.1:9050, auto_config_url=none) — other programs "
                    "routed through this proxy."
                ),
            }
        ]
        annotated = _annotate(findings, "ProxySettings")
        assert annotated[0]["proxy_enabled"] is True
        assert annotated[0]["proxy_server"] == "127.0.0.1:9050"
        assert annotated[0]["auto_config_url"] is None
