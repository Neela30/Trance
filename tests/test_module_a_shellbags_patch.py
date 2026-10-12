"""Regression tests for _shellbags_patch.py -- the fix for a confirmed real-world bug:
extension_block.get_creation_time() (a pyfwsi C extension method) raises SystemError on
certain real entries, which regipy's own ShellBagUsrclassPlugin.iter_sk() only guards
against with `except OSError:` -- the SystemError propagates straight through, aborting
the ENTIRE ShellBags extraction (not just the one bad item). See _shellbags_patch.py's
own module docstring for the full root-cause writeup (reproduced and proven against a
real UsrClass.dat hive, not guessed).

A real pyfwsi is never required here -- a minimal fake module, installed into
sys.modules for the duration of each test, stands in for it. Per this file's own
established "never touch real evidence" rule, no real hive is used.
"""

from __future__ import annotations

import sys
import types
from unittest.mock import MagicMock

import pytest
from regipy.plugins.usrclass.shellbags_usrclass import ShellBagUsrclassPlugin

from modules.module_a_registry._shellbags_patch import apply_shellbags_patch


class _FakeTimestamp:
    def isoformat(self):
        return "2026-01-01T00:00:00"


class _FakeFileEntryExtension:
    """Stands in for pyfwsi.file_entry_extension -- a real class (not a MagicMock) so
    `isinstance(extension_block, pyfwsi.file_entry_extension)` in the patched method
    behaves exactly like it does against the real C extension type."""

    def __init__(self, creation_exc=None, access_exc=None):
        self.long_name = None
        self._creation_exc = creation_exc
        self._access_exc = access_exc

    def get_creation_time(self):
        if self._creation_exc:
            raise self._creation_exc
        return _FakeTimestamp()

    def get_access_time(self):
        if self._access_exc:
            raise self._access_exc
        return _FakeTimestamp()


class _FakeFileEntry:
    """Stands in for pyfwsi.file_entry -- enough for
    ShellBagUsrclassPlugin._parse_shell_item_path_segment() to resolve a plain string
    path segment from `.name`, with no extension block long_name override."""

    def __init__(self, name, extension_blocks=()):
        self.name = name
        self.extension_blocks = list(extension_blocks)


class _FakeVolume:
    pass


class _FakeNetworkLocation:
    pass


class _FakeRootFolder:
    pass


class _FakeControlPanelCategory:
    pass


class _FakeControlPanelItem:
    pass


class _FakeUsersPropertyView:
    pass


class _FakeItemList:
    """Stands in for pyfwsi.item_list() -- copy_from_byte_stream() here just unpacks
    whatever list of fake items the test put in `v.value` directly (skipping real PIDL
    byte decoding entirely, since that's not what this patch changes or needs to test)."""

    def __init__(self):
        self.items = []

    def copy_from_byte_stream(self, data, ascii_codepage=None):
        if data == b"RAISE":
            raise OSError("fake pyfwsi decode failure")
        self.items = list(data)


def _install_fake_pyfwsi() -> types.ModuleType:
    fake = types.ModuleType("pyfwsi")
    fake.item_list = _FakeItemList
    fake.file_entry_extension = _FakeFileEntryExtension
    fake.file_entry = _FakeFileEntry
    fake.volume = _FakeVolume
    fake.network_location = _FakeNetworkLocation
    fake.root_folder = _FakeRootFolder
    fake.control_panel_category = _FakeControlPanelCategory
    fake.control_panel_item = _FakeControlPanelItem
    fake.users_property_view = _FakeUsersPropertyView
    sys.modules["pyfwsi"] = fake
    return fake


@pytest.fixture(autouse=True)
def _fake_pyfwsi_module():
    """Deliberately NOT monkeypatch.setitem/delitem: monkeypatch's own undo stack
    restores whatever value a key had at the moment *it* changed it -- since the fake
    module was installed via a plain dict assignment (not through monkeypatch),
    monkeypatch.delitem's teardown would record "pyfwsi was the fake module" as the
    pre-delete state and put the FAKE module straight back into sys.modules once this
    fixture's own `monkeypatch` parameter finalized, leaking it into whichever real test
    (e.g. the real-hive integration test) imports pyfwsi next. Plain dict
    get/pop/assignment has no such undo semantics to fight."""
    original = sys.modules.get("pyfwsi")
    _install_fake_pyfwsi()
    yield
    if original is not None:
        sys.modules["pyfwsi"] = original
    else:
        sys.modules.pop("pyfwsi", None)


def _fake_value(name: str, items) -> MagicMock:
    v = MagicMock()
    v.name = name
    v.value = items
    return v


def _mru_bytes(*indices: int) -> bytes:
    """Builds the same little-endian, trailing-terminator-stripped MRUListEx shape
    ShellBagUsrclassPlugin._parse_mru() expects -- real slot values are matched against
    this by exact string (mru_order.split("-").index(value_name)), so a test with N
    slots needs all N indices actually present here, in order."""
    return b"".join(i.to_bytes(4, "little") for i in indices) + b"\xff\xff\xff\xff"


def _make_key(values: list, mru_indices: tuple[int, ...] = (0,)) -> MagicMock:
    key = MagicMock()
    key.header.last_modified = 0
    key.get_value.side_effect = lambda name: (
        _mru_bytes(*mru_indices) if name == "MRUListEx" else None
    )
    key.iter_values.return_value = values
    return key


def _empty_key() -> MagicMock:
    """A key with no digit-named values -- recursion into it (plugin.registry_hive.get_key())
    terminates immediately with nothing further to process."""
    key = MagicMock()
    key.header.last_modified = 0
    key.get_value.return_value = None
    key.iter_values.return_value = []
    return key


def _make_plugin() -> ShellBagUsrclassPlugin:
    apply_shellbags_patch()
    registry_hive = MagicMock()
    registry_hive.get_key.return_value = _empty_key()
    return ShellBagUsrclassPlugin(registry_hive, as_json=True)


class TestShellbagsPatchSystemErrorHandling:
    def test_system_error_on_creation_time_does_not_abort_the_entry(self):
        """The exact confirmed bug: get_creation_time() raises SystemError (not the
        OSError regipy's own code already guards against) -- the patched method must
        still produce an entry (with creation_time=None) instead of propagating."""
        plugin = _make_plugin()
        extension = _FakeFileEntryExtension(
            creation_exc=SystemError("invalid format string: %hhu.")
        )
        item = _FakeFileEntry("Tor Browser", extension_blocks=[extension])

        key = _make_key([_fake_value("0", [item])])

        plugin.iter_sk(key, r"\Local Settings\Software\Microsoft\Windows\Shell\BagMRU")

        assert len(plugin.entries) == 1
        assert plugin.entries[0]["path"] == "Tor Browser"
        assert plugin.entries[0]["creation_time"] is None

    def test_system_error_on_access_time_does_not_abort_the_entry(self):
        plugin = _make_plugin()
        extension = _FakeFileEntryExtension(access_exc=SystemError("invalid format string: %hhu."))
        item = _FakeFileEntry("Downloads", extension_blocks=[extension])

        key = _make_key([_fake_value("0", [item])])

        plugin.iter_sk(key, r"\Local Settings\Software\Microsoft\Windows\Shell\BagMRU")

        assert len(plugin.entries) == 1
        assert plugin.entries[0]["access_time"] is None

    def test_ordinary_oserror_still_handled_same_as_before(self):
        """Confirms the patch is additive (OSError, SystemError), not a replacement --
        regipy's own original OSError handling for a genuinely malformed timestamp must
        keep working exactly as it did before this patch existed."""
        plugin = _make_plugin()
        extension = _FakeFileEntryExtension(creation_exc=OSError("malformed timestamp"))
        item = _FakeFileEntry("Pictures", extension_blocks=[extension])

        key = _make_key([_fake_value("0", [item])])

        plugin.iter_sk(key, r"\Local Settings\Software\Microsoft\Windows\Shell\BagMRU")

        assert len(plugin.entries) == 1
        assert plugin.entries[0]["creation_time"] is None

    def test_successful_timestamp_read_is_unaffected(self):
        plugin = _make_plugin()
        extension = _FakeFileEntryExtension()
        item = _FakeFileEntry("Documents", extension_blocks=[extension])

        key = _make_key([_fake_value("0", [item])])

        plugin.iter_sk(key, r"\Local Settings\Software\Microsoft\Windows\Shell\BagMRU")

        assert plugin.entries[0]["creation_time"] == "2026-01-01T00:00:00"


class TestShellbagsPatchPerSlotIsolation:
    def test_one_bad_slot_does_not_abort_sibling_slots(self):
        """Defense-in-depth layer: if an entire slot's byte-stream decode fails for some
        OTHER reason pyfwsi might raise (not just the known SystemError), sibling slots
        at the same level must still be processed and counted as skipped, not silently
        lost along with everything after them."""
        plugin = _make_plugin()
        good_item = _FakeFileEntry("E:\\Tor Browser")

        key = _make_key(
            [
                _fake_value("0", b"RAISE"),  # triggers _FakeItemList.copy_from_byte_stream's raise
                _fake_value("1", [good_item]),
            ],
            mru_indices=(0, 1),
        )

        plugin.iter_sk(key, r"\Local Settings\Software\Microsoft\Windows\Shell\BagMRU")

        assert plugin._shellbags_skip_count == 1
        assert len(plugin.entries) == 1
        assert plugin.entries[0]["path"] == "E:\\Tor Browser"

    def test_no_skips_when_everything_succeeds(self):
        plugin = _make_plugin()
        item = _FakeFileEntry("Desktop")

        key = _make_key([_fake_value("0", [item])])

        plugin.iter_sk(key, r"\Local Settings\Software\Microsoft\Windows\Shell\BagMRU")

        assert getattr(plugin, "_shellbags_skip_count", 0) == 0
        assert len(plugin.entries) == 1


class TestApplyShellbagsPatchIdempotent:
    def test_applying_twice_does_not_double_wrap(self):
        apply_shellbags_patch()
        first = ShellBagUsrclassPlugin.iter_sk
        apply_shellbags_patch()
        second = ShellBagUsrclassPlugin.iter_sk
        assert first is second
