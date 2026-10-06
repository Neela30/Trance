"""Tests for custom_extractors.py (Phase 1 of the Module A roadmap) -- registry
artifacts with no regipy plugin at all. Per this project's "never touch real evidence"
rule, RegistryHive is mocked out throughout, same pattern Phase 0 established for the
(now-removed) system_context.py.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from regipy.exceptions import RegistryKeyNotFoundException

from modules.module_a_registry.custom_extractors import (
    extract_app_switched,
    extract_compat_assistant_store,
    extract_emdmgmt,
    extract_firefox_launcher,
    extract_mountpoints2,
    extract_muicache_usrclass,
    extract_portable_devices,
)


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


def _fake_subkey(name: str, values: dict | None = None, last_modified: int = 0) -> MagicMock:
    subkey = MagicMock()
    subkey.name = name
    subkey.header.last_modified = last_modified
    subkey.get_value.side_effect = lambda value_name: (values or {}).get(value_name)
    return subkey


class TestMuicacheUsrclass:
    def test_happy_path_skips_at_values_and_langid(self, tmp_path):
        usrclass_path = tmp_path / "UsrClass.dat"
        usrclass_path.write_bytes(b"synthetic")

        values = [
            _fake_value(r"E:\Tor Browser\Browser\firefox.exe", "Tor Browser"),
            _fake_value("@shell32.dll,-21805", "ignored"),
            _fake_value("LangID", 1033),
        ]
        fake_hive = MagicMock()
        fake_hive.get_key.return_value = _fake_key(values)

        with patch(
            "modules.module_a_registry.custom_extractors.RegistryHive", return_value=fake_hive
        ):
            result = extract_muicache_usrclass(usrclass_path)

        assert len(result) == 1
        assert result[0]["path"] == r"E:\Tor Browser\Browser\firefox.exe"
        assert result[0]["display_name"] == "Tor Browser"

    def test_missing_key_returns_empty_list(self, tmp_path):
        usrclass_path = tmp_path / "UsrClass.dat"
        usrclass_path.write_bytes(b"synthetic")

        fake_hive = MagicMock()
        fake_hive.get_key.side_effect = RegistryKeyNotFoundException("missing")

        with patch(
            "modules.module_a_registry.custom_extractors.RegistryHive", return_value=fake_hive
        ):
            result = extract_muicache_usrclass(usrclass_path)

        assert result == []


class TestCompatAssistantStore:
    def test_path_is_the_value_name(self, tmp_path):
        ntuser_path = tmp_path / "NTUSER.DAT"
        ntuser_path.write_bytes(b"synthetic")

        values = [_fake_value(r"E:\Tor Browser\Browser\firefox.exe", b"\x00" * 16)]
        fake_hive = MagicMock()
        fake_hive.get_key.return_value = _fake_key(values)

        with patch(
            "modules.module_a_registry.custom_extractors.RegistryHive", return_value=fake_hive
        ):
            result = extract_compat_assistant_store(ntuser_path)

        assert result[0]["path"] == r"E:\Tor Browser\Browser\firefox.exe"
        assert result[0]["data_size"] == 16

    def test_implausible_trailing_filetime_is_not_reported(self, tmp_path):
        ntuser_path = tmp_path / "NTUSER.DAT"
        ntuser_path.write_bytes(b"synthetic")

        # All-zero trailing 8 bytes decode to FILETIME 0 -- explicitly rejected rather
        # than reported as a real (1601-01-01) date.
        values = [_fake_value(r"C:\app.exe", b"\x00" * 16)]
        fake_hive = MagicMock()
        fake_hive.get_key.return_value = _fake_key(values)

        with patch(
            "modules.module_a_registry.custom_extractors.RegistryHive", return_value=fake_hive
        ):
            result = extract_compat_assistant_store(ntuser_path)

        assert result[0]["flagged_timestamp"] is None

    def test_missing_key_returns_empty_list(self, tmp_path):
        ntuser_path = tmp_path / "NTUSER.DAT"
        ntuser_path.write_bytes(b"synthetic")

        fake_hive = MagicMock()
        fake_hive.get_key.side_effect = RegistryKeyNotFoundException("missing")

        with patch(
            "modules.module_a_registry.custom_extractors.RegistryHive", return_value=fake_hive
        ):
            result = extract_compat_assistant_store(ntuser_path)

        assert result == []


class TestFirefoxLauncher:
    def test_path_is_the_value_name(self, tmp_path):
        ntuser_path = tmp_path / "NTUSER.DAT"
        ntuser_path.write_bytes(b"synthetic")

        values = [_fake_value(r"E:\Tor Browser\Browser\firefox.exe", "SET")]
        fake_hive = MagicMock()
        fake_hive.get_key.return_value = _fake_key(values)

        with patch(
            "modules.module_a_registry.custom_extractors.RegistryHive", return_value=fake_hive
        ):
            result = extract_firefox_launcher(ntuser_path)

        assert result[0]["path"] == r"E:\Tor Browser\Browser\firefox.exe"

    def test_missing_key_returns_empty_list(self, tmp_path):
        ntuser_path = tmp_path / "NTUSER.DAT"
        ntuser_path.write_bytes(b"synthetic")

        fake_hive = MagicMock()
        fake_hive.get_key.side_effect = RegistryKeyNotFoundException("missing")

        with patch(
            "modules.module_a_registry.custom_extractors.RegistryHive", return_value=fake_hive
        ):
            result = extract_firefox_launcher(ntuser_path)

        assert result == []


class TestAppSwitched:
    def test_switch_count_is_read_as_int(self, tmp_path):
        ntuser_path = tmp_path / "NTUSER.DAT"
        ntuser_path.write_bytes(b"synthetic")

        values = [_fake_value(r"E:\Tor Browser\Browser\firefox.exe", 7)]
        fake_hive = MagicMock()
        fake_hive.get_key.return_value = _fake_key(values)

        with patch(
            "modules.module_a_registry.custom_extractors.RegistryHive", return_value=fake_hive
        ):
            result = extract_app_switched(ntuser_path)

        assert result[0]["switch_count"] == 7

    def test_missing_key_returns_empty_list(self, tmp_path):
        ntuser_path = tmp_path / "NTUSER.DAT"
        ntuser_path.write_bytes(b"synthetic")

        fake_hive = MagicMock()
        fake_hive.get_key.side_effect = RegistryKeyNotFoundException("missing")

        with patch(
            "modules.module_a_registry.custom_extractors.RegistryHive", return_value=fake_hive
        ):
            result = extract_app_switched(ntuser_path)

        assert result == []


class TestMountPoints2:
    def test_subkey_name_is_the_path(self, tmp_path):
        ntuser_path = tmp_path / "NTUSER.DAT"
        ntuser_path.write_bytes(b"synthetic")

        subkey = _fake_subkey(
            r"_??_USBSTOR#Disk&Ven_SanDisk&Prod_Cruzer_Blade&Rev_1.00#4C53000012345678&0#"
            r"{53f5630d-b6bf-11d0-94f2-00a0c91efb8b}"
        )
        key = MagicMock()
        key.iter_subkeys.return_value = [subkey]
        fake_hive = MagicMock()
        fake_hive.get_key.return_value = key

        with patch(
            "modules.module_a_registry.custom_extractors.RegistryHive", return_value=fake_hive
        ):
            result = extract_mountpoints2(ntuser_path)

        assert len(result) == 1
        assert result[0]["path"] == subkey.name

    def test_missing_key_returns_empty_list(self, tmp_path):
        ntuser_path = tmp_path / "NTUSER.DAT"
        ntuser_path.write_bytes(b"synthetic")

        fake_hive = MagicMock()
        fake_hive.get_key.side_effect = RegistryKeyNotFoundException("missing")

        with patch(
            "modules.module_a_registry.custom_extractors.RegistryHive", return_value=fake_hive
        ):
            result = extract_mountpoints2(ntuser_path)

        assert result == []


class TestEmdmgmt:
    def test_device_capacity_is_read(self, tmp_path):
        software_path = tmp_path / "SOFTWARE"
        software_path.write_bytes(b"synthetic")

        subkey = _fake_subkey("SanDisk_Cruzer_Blade", values={"DeviceCapacity": 8192})
        key = MagicMock()
        key.iter_subkeys.return_value = [subkey]
        fake_hive = MagicMock()
        fake_hive.get_key.return_value = key

        with patch(
            "modules.module_a_registry.custom_extractors.RegistryHive", return_value=fake_hive
        ):
            result = extract_emdmgmt(software_path)

        assert result[0]["path"] == "SanDisk_Cruzer_Blade"
        assert result[0]["device_capacity"] == 8192

    def test_missing_key_returns_empty_list(self, tmp_path):
        software_path = tmp_path / "SOFTWARE"
        software_path.write_bytes(b"synthetic")

        fake_hive = MagicMock()
        fake_hive.get_key.side_effect = RegistryKeyNotFoundException("missing")

        with patch(
            "modules.module_a_registry.custom_extractors.RegistryHive", return_value=fake_hive
        ):
            result = extract_emdmgmt(software_path)

        assert result == []


class TestPortableDevices:
    def test_friendly_name_is_read_per_control_set(self, tmp_path):
        system_path = tmp_path / "SYSTEM"
        system_path.write_bytes(b"synthetic")

        device_subkey = _fake_subkey("5&abc123", values={"FriendlyName": "My Phone"})
        wpd_key = MagicMock()
        wpd_key.iter_subkeys.return_value = [device_subkey]
        fake_hive = MagicMock()
        fake_hive.get_control_sets.return_value = [r"\ControlSet001\Enum\SWD\WPDBUSENUM"]
        fake_hive.get_key.return_value = wpd_key

        with patch(
            "modules.module_a_registry.custom_extractors.RegistryHive", return_value=fake_hive
        ):
            result = extract_portable_devices(system_path)

        assert len(result) == 1
        assert result[0]["friendly_name"] == "My Phone"
        assert result[0]["path"] == "5&abc123"

    def test_missing_control_set_key_is_skipped_gracefully(self, tmp_path):
        system_path = tmp_path / "SYSTEM"
        system_path.write_bytes(b"synthetic")

        fake_hive = MagicMock()
        fake_hive.get_control_sets.return_value = [r"\ControlSet001\Enum\SWD\WPDBUSENUM"]
        fake_hive.get_key.side_effect = RegistryKeyNotFoundException("missing")

        with patch(
            "modules.module_a_registry.custom_extractors.RegistryHive", return_value=fake_hive
        ):
            result = extract_portable_devices(system_path)

        assert result == []

    def test_no_control_sets_returns_empty_list(self, tmp_path):
        system_path = tmp_path / "SYSTEM"
        system_path.write_bytes(b"synthetic")

        fake_hive = MagicMock()
        fake_hive.get_control_sets.return_value = []

        with patch(
            "modules.module_a_registry.custom_extractors.RegistryHive", return_value=fake_hive
        ):
            result = extract_portable_devices(system_path)

        assert result == []
