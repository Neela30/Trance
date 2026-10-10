"""Tests for Phase 3 of the Module A roadmap -- network context (NetworkList profiles/
signatures from SOFTWARE, Tcpip interfaces from SYSTEM), plus the shared command-line/
proxy predicates added to constants.py that Phase 4 also depends on.

RegistryHive/plugins are mocked throughout, per this project's "never touch real
evidence" rule -- real-hive behavior was verified manually (see extractors.py's
docstrings) before writing these.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from regipy.exceptions import RegistryKeyNotFoundException

from modules.module_a_registry import constants
from modules.module_a_registry.extractors import (
    extract_network_interfaces,
    extract_network_profiles,
)
from modules.module_a_registry.narrative import (
    build_network_narrative,
    describe_closest_network_before_launch,
    describe_dhcp_leases_covering_launch,
    describe_networks_created_same_day_as_launch,
    find_latest_tor_use_iso,
    local_systemtime_to_utc,
)
from modules.module_a_registry.normalize import normalize_entry
from modules.module_a_registry.report import _build_network_context, _extract_timezone_bias


def _fake_value(name: str, value) -> MagicMock:
    v = MagicMock()
    v.name = name
    v.value = value
    return v


def _fake_subkey(name: str, values: list, last_modified: int = 0) -> MagicMock:
    subkey = MagicMock()
    subkey.name = name
    subkey.header.last_modified = last_modified
    subkey.iter_values.return_value = values
    return subkey


# A real decoded SYSTEMTIME blob: 2025-03-26 08:57:11 local (little-endian
# Year/Month/DayOfWeek/Day/Hour/Minute/Second/Milliseconds WORDs) -- matches the value
# manually decoded against the real evidence hive during planning.
_REAL_DATE_CREATED_BYTES = bytes.fromhex("e907030003001a00080039000b005000")
_REAL_MAC_BYTES = bytes.fromhex("e47deb7a4551")


class TestExtractNetworkProfiles:
    def test_profile_joined_with_signature(self, tmp_path):
        software_path = tmp_path / "SOFTWARE"
        software_path.write_bytes(b"synthetic")

        profile_subkey = _fake_subkey(
            "{GUID-1}",
            [
                _fake_value("ProfileName", "Home Wifi"),
                _fake_value("Description", "Home Wifi"),
                _fake_value("NameType", 0x47),
                _fake_value("Category", 0),
                _fake_value("DateCreated", _REAL_DATE_CREATED_BYTES),
                _fake_value("DateLastConnected", _REAL_DATE_CREATED_BYTES),
            ],
        )
        profiles_key = MagicMock()
        profiles_key.iter_subkeys.return_value = [profile_subkey]

        sig_subkey = _fake_subkey(
            "SIGID1",
            [
                _fake_value("ProfileGuid", "{GUID-1}"),
                _fake_value("DefaultGatewayMac", _REAL_MAC_BYTES),
                _fake_value("DnsSuffix", "<none>"),
                _fake_value("FirstNetwork", "Home Wifi"),
            ],
        )
        unmanaged_key = MagicMock()
        unmanaged_key.iter_subkeys.return_value = [sig_subkey]

        def get_key(path):
            if path.endswith("Profiles"):
                return profiles_key
            if path.endswith("Unmanaged"):
                return unmanaged_key
            raise RegistryKeyNotFoundException(path)

        fake_hive = MagicMock()
        fake_hive.get_key.side_effect = get_key

        with patch("modules.module_a_registry.extractors.RegistryHive", return_value=fake_hive):
            result = extract_network_profiles(software_path)

        assert len(result) == 1
        entry = result[0]
        assert entry["profile_name"] == "Home Wifi"
        assert entry["name_type"] == "Wireless"
        assert entry["category"] == "Public"
        assert entry["date_created_local"] == "2025-03-26T08:57:11"
        assert entry["date_last_connected_local"] == "2025-03-26T08:57:11"
        assert entry["default_gateway_mac"] == "E4:7D:EB:7A:45:51"
        assert entry["signature_type"] == "unmanaged"
        assert entry["dns_suffix"] == "<none>"

    def test_profile_with_no_matching_signature_still_returned(self, tmp_path):
        software_path = tmp_path / "SOFTWARE"
        software_path.write_bytes(b"synthetic")

        profile_subkey = _fake_subkey("{GUID-LONE}", [_fake_value("ProfileName", "Lone Network")])
        profiles_key = MagicMock()
        profiles_key.iter_subkeys.return_value = [profile_subkey]

        def get_key(path):
            if path.endswith("Profiles"):
                return profiles_key
            raise RegistryKeyNotFoundException(path)

        fake_hive = MagicMock()
        fake_hive.get_key.side_effect = get_key

        with patch("modules.module_a_registry.extractors.RegistryHive", return_value=fake_hive):
            result = extract_network_profiles(software_path)

        assert len(result) == 1
        assert result[0]["profile_name"] == "Lone Network"
        assert "default_gateway_mac" not in result[0]

    def test_no_profiles_key_at_all_returns_empty_list(self, tmp_path):
        software_path = tmp_path / "SOFTWARE"
        software_path.write_bytes(b"synthetic")

        fake_hive = MagicMock()
        fake_hive.get_key.side_effect = RegistryKeyNotFoundException("missing")

        with patch("modules.module_a_registry.extractors.RegistryHive", return_value=fake_hive):
            result = extract_network_profiles(software_path)

        assert result == []

    def test_broken_hex_string_date_is_not_crashed_on(self, tmp_path):
        """Confirms the fix: a value read via iter_values(trim_values=False) must be real
        bytes before parse_network_date() is called -- if it somehow isn't (e.g. a hex
        string from some other code path), the date is simply skipped, never crashes or
        silently mis-decodes."""
        software_path = tmp_path / "SOFTWARE"
        software_path.write_bytes(b"synthetic")

        profile_subkey = _fake_subkey(
            "{GUID-HEX}",
            [
                _fake_value("ProfileName", "Weird Entry"),
                _fake_value("DateCreated", "e907030003001a00080039000b005000"),  # str, not bytes
            ],
        )
        profiles_key = MagicMock()
        profiles_key.iter_subkeys.return_value = [profile_subkey]

        fake_hive = MagicMock()
        fake_hive.get_key.side_effect = lambda path: (
            profiles_key
            if path.endswith("Profiles")
            else (_ for _ in ()).throw(RegistryKeyNotFoundException(path))
        )

        with patch("modules.module_a_registry.extractors.RegistryHive", return_value=fake_hive):
            result = extract_network_profiles(software_path)

        assert "date_created_local" not in result[0]


class TestExtractNetworkInterfaces:
    def test_flattens_interfaces_and_drops_sub_interface(self, tmp_path):
        system_path = tmp_path / "SYSTEM"
        system_path.write_bytes(b"synthetic")

        fake_plugin = MagicMock()
        fake_plugin.can_run.return_value = True
        fake_plugin.entries = {
            r"\ControlSet001\Services\Tcpip\Parameters\Interfaces": {
                "timestamp": "2026-01-01T00:00:00+00:00",
                "interfaces": [
                    {
                        "interface_name": "{IFACE-1}",
                        "last_modified": "2026-01-01T00:00:00+00:00",
                        "dhcp_enabled": True,
                        "dhcp_ip_address": "192.168.1.10",
                        "dhcp_server": "192.168.1.1",
                        "dhcp_default_gateway": ["192.168.1.1"],
                        "dhcp_lease_obtained_time": "2026-01-01 00:00:00",
                        "dhcp_lease_terminates_time": "2026-01-02 00:00:00",
                        "sub_interface": [{"interface_name": "garbage"}],
                    }
                ],
            }
        }

        with (
            patch("modules.module_a_registry.extractors.RegistryHive", return_value=MagicMock()),
            patch(
                "modules.module_a_registry.extractors.NetworkDataPlugin", return_value=fake_plugin
            ),
        ):
            result = extract_network_interfaces(system_path)

        assert len(result) == 1
        assert "sub_interface" not in result[0]
        assert result[0]["interface_name"] == "{IFACE-1}"
        assert result[0]["key_path"].endswith("{IFACE-1}")

    def test_cannot_run_raises_parsing_error(self, tmp_path):
        from core.exceptions import ParsingError

        system_path = tmp_path / "SYSTEM"
        system_path.write_bytes(b"synthetic")

        fake_plugin = MagicMock()
        fake_plugin.can_run.return_value = False

        with (
            patch("modules.module_a_registry.extractors.RegistryHive", return_value=MagicMock()),
            patch(
                "modules.module_a_registry.extractors.NetworkDataPlugin", return_value=fake_plugin
            ),
        ):
            try:
                extract_network_interfaces(system_path)
                assert False, "expected ParsingError"
            except ParsingError:
                pass


class TestCommandExecutableExtraction:
    def test_quoted_path_with_arguments(self):
        assert (
            constants.extract_command_executable(r'"C:\Tor\tor.exe" --service') == r"C:\Tor\tor.exe"
        )

    def test_unquoted_path_with_arguments(self):
        assert (
            constants.extract_command_executable(r"%SystemRoot%\System32\svchost.exe -k Group")
            == r"%SystemRoot%\System32\svchost.exe"
        )

    def test_bare_path_no_arguments(self):
        assert constants.extract_command_executable(r"C:\Tor\tor.exe") == r"C:\Tor\tor.exe"

    def test_none_and_empty(self):
        assert constants.extract_command_executable(None) is None
        assert constants.extract_command_executable("") is None


class TestServiceNameAndProxyPredicates:
    def test_is_tor_service_name_matches_known_variants(self):
        assert constants.is_tor_service_name("tor")
        assert constants.is_tor_service_name("Tor")
        assert constants.is_tor_service_name(" Tor Service ")
        assert not constants.is_tor_service_name("storvsc")
        assert not constants.is_tor_service_name(None)

    def test_proxy_enabled_and_socks_port_matches(self):
        assert constants.is_tor_proxy_config({"proxy_enable": 1, "proxy_server": "127.0.0.1:9050"})
        assert constants.is_tor_proxy_config({"proxy_enable": 1, "proxy_server": "localhost:9150"})

    def test_proxy_multi_protocol_string_matches_socks_segment(self):
        assert constants.is_tor_proxy_config(
            {
                "proxy_enable": 1,
                "proxy_server": "ftp=1.2.3.4:21;http=1.2.3.4:80;socks=127.0.0.1:9050",
            }
        )

    def test_proxy_disabled_does_not_match_even_with_right_port(self):
        assert not constants.is_tor_proxy_config(
            {"proxy_enable": 0, "proxy_server": "127.0.0.1:9050"}
        )

    def test_proxy_enabled_but_wrong_port_or_host_does_not_match(self):
        assert not constants.is_tor_proxy_config(
            {"proxy_enable": 1, "proxy_server": "10.10.3.92:80"}
        )
        assert not constants.is_tor_proxy_config(
            {"proxy_enable": 1, "proxy_server": "1.2.3.4:9050"}
        )

    def test_proxy_missing_server(self):
        assert not constants.is_tor_proxy_config({"proxy_enable": 1})

    def test_is_tor_related_entry_dispatches_proxy_settings(self):
        assert constants.is_tor_related_entry(
            "ProxySettings", {"proxy_enable": 1, "proxy_server": "127.0.0.1:9050"}
        )
        assert not constants.is_tor_related_entry(
            "ProxySettings", {"proxy_enable": 0, "proxy_server": "127.0.0.1:9050"}
        )

    def test_is_tor_related_entry_matches_service_by_name_even_with_unrelated_exe(self):
        # A Tor service wrapped by nssm.exe (ImagePath doesn't look Tor-related at all,
        # but the service's own name does) -- must still be caught.
        assert constants.is_tor_related_entry(
            "Service", {"name": "tor", "executable": r"C:\nssm.exe"}
        )

    def test_is_tor_related_entry_matches_service_by_executable_path(self):
        assert constants.is_tor_related_entry(
            "Service", {"name": "SomeOtherName", "executable": r"C:\Tor\tor.exe"}
        )

    def test_is_tor_related_entry_rejects_unrelated_service(self):
        assert not constants.is_tor_related_entry(
            "Service", {"name": "RtkAudUService", "executable": r"C:\RtkAudUService64.exe"}
        )


class TestNormalizeNetworkContext:
    def test_normalize_network_profile_renders_all_fields(self):
        entry = {
            "profile_guid": "{GUID-1}",
            "profile_name": "Home Wifi",
            "name_type": "Wireless",
            "category": "Public",
            "date_created_local": "2025-03-26T08:57:11",
            "date_last_connected_local": "2025-08-23T17:07:52",
            "default_gateway_mac": "E4:7D:EB:7A:45:51",
            "dns_suffix": "<none>",
        }
        artifact = normalize_entry("NetworkProfile", entry, "SOFTWARE")
        assert artifact.category == "context"
        assert artifact.confidence == "high"
        assert "Home Wifi" in artifact.description
        assert artifact.timestamp is None  # never promoted -- see normalize.py docstring

    def test_normalize_network_profile_missing_fields_show_unknown(self):
        artifact = normalize_entry("NetworkProfile", {"profile_guid": "{X}"}, "SOFTWARE")
        assert "unknown" in artifact.description

    def test_normalize_network_interface_dhcp_variant(self):
        entry = {
            "interface_name": "{IFACE}",
            "dhcp_enabled": True,
            "dhcp_ip_address": "192.168.1.10",
            "dhcp_default_gateway": ["192.168.1.1"],
            "dhcp_server": "192.168.1.1",
            "dhcp_lease_obtained_time": "2026-01-01 00:00:00",
            "dhcp_lease_terminates_time": "2026-01-02 00:00:00",
            "last_modified": "2026-01-01T00:00:00+00:00",
        }
        artifact = normalize_entry("NetworkInterface", entry, "SYSTEM")
        assert "dhcp=yes" in artifact.description
        assert artifact.timestamp == "2026-01-01T00:00:00+00:00"

    def test_normalize_network_interface_static_variant(self):
        entry = {
            "interface_name": "{IFACE}",
            "dhcp_enabled": False,
            "ip_address": ["192.168.56.1"],
            "default_gateway": None,
            "domain": "",
        }
        artifact = normalize_entry("NetworkInterface", entry, "SYSTEM")
        assert "dhcp=no" in artifact.description
        assert "192.168.56.1" in artifact.description


class TestLocalSystemtimeToUtc:
    def test_sri_lanka_bias_negative_330(self):
        # Confirmed against real evidence: Sri Lanka Standard Time (UTC+5:30) recorded
        # Bias=-330 -- UTC = local + bias, so local 08:57:11 -> UTC 03:27:11.
        result = local_systemtime_to_utc("2025-03-26T08:57:11", -330)
        assert result == "2025-03-26T03:27:11+00:00"

    def test_us_eastern_bias_positive_300(self):
        # US Eastern (UTC-5) is recorded as Bias=+300 -- UTC = local + bias.
        result = local_systemtime_to_utc("2026-01-01T10:00:00", 300)
        assert result == "2026-01-01T15:00:00+00:00"

    def test_zero_bias_is_utc_itself(self):
        result = local_systemtime_to_utc("2026-01-01T10:00:00", 0)
        assert result == "2026-01-01T10:00:00+00:00"


class TestFindLatestTorUseIso:
    def test_no_launch_candidates_returns_none(self):
        assert find_latest_tor_use_iso({"UserAssist": []}, []) is None

    def test_picks_latest_run_count_launch(self):
        annotated = {
            "UserAssist": [
                {
                    "path": r"E:\Tor Browser\Browser\firefox.exe",
                    "run_count": 1,
                    "timestamp": "2026-01-01T00:00:00+00:00",
                },
                {
                    "path": r"E:\Tor Browser\Browser\firefox.exe",
                    "run_count": 2,
                    "timestamp": "2026-01-05T00:00:00+00:00",
                },
            ]
        }
        assert find_latest_tor_use_iso(annotated, []) == "2026-01-05T00:00:00+00:00"

    def test_bam_does_not_move_the_launch_time(self):
        # A later BAM time is usually the program stopping, not a new opening: on a real
        # capture it was the browser's exit, ten minutes after the launch. The network
        # correlation needs the launch instant.
        from datetime import datetime, timezone

        annotated = {
            "UserAssist": [
                {
                    "path": r"E:\Tor Browser\Browser\firefox.exe",
                    "run_count": 1,
                    "timestamp": "2026-01-01T00:00:00+00:00",
                },
            ]
        }
        component_timeline = [{"bam_last_run": datetime(2026, 1, 2, 0, 0, 0, tzinfo=timezone.utc)}]
        assert find_latest_tor_use_iso(annotated, component_timeline) == (
            "2026-01-01T00:00:00+00:00"
        )


class TestNetworkCorrelationRules:
    def test_closest_network_before_launch(self):
        from datetime import datetime, timezone

        profiles = [
            {
                "profile_name": "Old Network",
                "gateway_mac": "AA:BB:CC:DD:EE:FF",
                "_last_connected_utc_dt": datetime(2026, 1, 1, tzinfo=timezone.utc),
            },
            {
                "profile_name": "Recent Network",
                "gateway_mac": "11:22:33:44:55:66",
                "_last_connected_utc_dt": datetime(2026, 1, 4, tzinfo=timezone.utc),
            },
            {
                # After the launch -- must not be picked.
                "profile_name": "Future Network",
                "_last_connected_utc_dt": datetime(2026, 1, 10, tzinfo=timezone.utc),
            },
        ]
        sentence = describe_closest_network_before_launch(profiles, "2026-01-05T00:00:00+00:00")
        assert "Recent Network" in sentence
        assert "11:22:33:44:55:66" in sentence
        assert "Future Network" not in sentence
        assert "while using Tor" not in sentence

    def test_closest_network_no_candidates_before_launch(self):
        from datetime import datetime, timezone

        profiles = [
            {
                "profile_name": "Future",
                "_last_connected_utc_dt": datetime(2026, 1, 10, tzinfo=timezone.utc),
            }
        ]
        assert describe_closest_network_before_launch(profiles, "2026-01-05T00:00:00+00:00") is None

    def test_no_latest_use_returns_none(self):
        assert describe_closest_network_before_launch([{"profile_name": "X"}], None) is None

    def test_networks_created_same_day(self):
        from datetime import datetime, timezone

        profiles = [
            {
                "profile_name": "Same Day Net",
                "_created_utc_dt": datetime(2026, 1, 5, 2, 0, tzinfo=timezone.utc),
            },
            {
                "profile_name": "Other Day Net",
                "_created_utc_dt": datetime(2026, 1, 1, tzinfo=timezone.utc),
            },
        ]
        sentences = describe_networks_created_same_day_as_launch(
            profiles, "2026-01-05T20:00:00+00:00"
        )
        assert len(sentences) == 1
        assert "Same Day Net" in sentences[0]

    def test_dhcp_lease_covers_launch(self):
        interfaces = [
            {
                "ip": "192.168.1.10",
                "lease_obtained_utc": "2026-01-05 00:00:00",
                "lease_terminates_utc": "2026-01-06 00:00:00",
            }
        ]
        sentences = describe_dhcp_leases_covering_launch(interfaces, "2026-01-05T12:00:00+00:00")
        assert len(sentences) == 1
        assert "192.168.1.10" in sentences[0]
        assert "not which network it was routed through" in sentences[0]

    def test_dhcp_lease_outside_window_produces_nothing(self):
        interfaces = [
            {
                "ip": "192.168.1.10",
                "lease_obtained_utc": "2026-01-05 00:00:00",
                "lease_terminates_utc": "2026-01-06 00:00:00",
            }
        ]
        sentences = describe_dhcp_leases_covering_launch(interfaces, "2026-02-01T12:00:00+00:00")
        assert sentences == []


class TestBuildNetworkNarrative:
    def test_timezone_unknown_skips_correlation_and_adds_caveat(self):
        profiles = [
            {
                "profile_name": "X",
                "created_local": "2026-01-01T00:00:00",
                "last_connected_local": "2026-01-01T00:00:00",
            }
        ]
        result = build_network_narrative(profiles, [], None, "2026-01-05T00:00:00+00:00")
        assert result["correlation"] == []
        assert any("time zone setting could not be determined" in c for c in result["caveats"])

    def test_no_profiles_no_caveats(self):
        result = build_network_narrative([], [], None, None)
        assert result == {"correlation": [], "caveats": []}

    def test_known_bias_produces_correlation_and_history_caveat(self):
        profiles = [
            {
                "profile_name": "Home",
                "gateway_mac": "AA:BB:CC:DD:EE:FF",
                "created_local": "2026-01-04T23:00:00",
                "last_connected_local": "2026-01-04T23:30:00",
            }
        ]
        result = build_network_narrative(profiles, [], 0, "2026-01-05T00:00:00+00:00")
        assert any("Home" in c for c in result["correlation"])
        assert any("only keeps one first-connected" in c for c in result["caveats"])
        assert not any("time zone setting could not be determined" in c for c in result["caveats"])


class TestBuildNetworkContext:
    def test_bias_extracted_from_system_context(self):
        system_context = {
            "TimeZone": {
                "description": "Windows time zone configured as 'X', bias=-330 minutes from UTC."
            }
        }
        assert _extract_timezone_bias(system_context) == -330

    def test_bias_none_when_timezone_missing(self):
        assert _extract_timezone_bias({}) is None

    def test_bias_none_when_timezone_has_no_bias(self):
        system_context = {
            "TimeZone": {"description": "Windows time zone configured as '<unknown>'."}
        }
        assert _extract_timezone_bias(system_context) is None

    def test_build_network_context_empty_when_no_findings(self):
        result = _build_network_context({}, {}, None)
        assert result["profiles"] == []
        assert result["interfaces"] == []
        assert result["bias_minutes"] is None
        assert result["narrative"] == {"correlation": [], "caveats": []}
