"""Tests for _muicache_grouping.group_muicache_values() -- confirmed real-world bug fix:
Windows Vista+ MuiCache stores TWO separate registry values per program
("<path>.FriendlyAppName" / "<path>.ApplicationCompany"), which both extract_muicache()
and extract_muicache_usrclass() used to treat as two unrelated findings."""

from __future__ import annotations

from modules.module_a_registry._muicache_grouping import group_muicache_values


def _raw(path, display_name):
    return {
        "key_path": r"\Local Settings\Software\Microsoft\Windows\Shell\MuiCache",
        "last_write": "2026-07-14T00:00:00+00:00",
        "path": path,
        "display_name": display_name,
        "filename": path.rsplit("\\", 1)[-1],
    }


class TestGroupMuicacheValues:
    def test_friendly_app_name_and_application_company_merge_into_one_record(self):
        raw = [
            _raw(r"E:\Tor Browser\Browser\firefox.exe.FriendlyAppName", "Tor Browser"),
            _raw(r"E:\Tor Browser\Browser\firefox.exe.ApplicationCompany", "Mozilla Corporation"),
        ]
        grouped = group_muicache_values(raw)

        assert len(grouped) == 1
        assert grouped[0]["path"] == r"E:\Tor Browser\Browser\firefox.exe"
        assert grouped[0]["filename"] == "firefox.exe"
        assert grouped[0]["display_name"] == "Tor Browser"
        assert grouped[0]["application_company"] == "Mozilla Corporation"

    def test_bare_unsuffixed_value_passes_through_as_its_own_group(self):
        """Pre-Vista/XP-era single-value convention -- no suffix, no separate company."""
        raw = [_raw(r"C:\Program Files\App\app.exe", "My App")]
        grouped = group_muicache_values(raw)

        assert len(grouped) == 1
        assert grouped[0]["path"] == r"C:\Program Files\App\app.exe"
        assert grouped[0]["display_name"] == "My App"
        assert grouped[0]["application_company"] is None

    def test_friendly_app_name_with_no_matching_company_still_groups(self):
        raw = [_raw(r"C:\x\app.exe.FriendlyAppName", "App")]
        grouped = group_muicache_values(raw)

        assert len(grouped) == 1
        assert grouped[0]["display_name"] == "App"
        assert grouped[0]["application_company"] is None

    def test_application_company_with_no_matching_friendly_name_still_groups(self):
        raw = [_raw(r"C:\x\app.exe.ApplicationCompany", "Some Corp")]
        grouped = group_muicache_values(raw)

        assert len(grouped) == 1
        assert grouped[0]["display_name"] is None
        assert grouped[0]["application_company"] == "Some Corp"

    def test_two_different_programs_stay_separate_and_order_preserved(self):
        raw = [
            _raw(r"E:\Tor Browser\Browser\firefox.exe.FriendlyAppName", "Tor Browser"),
            _raw(r"E:\Tor Browser\Browser\firefox.exe.ApplicationCompany", "Mozilla Corporation"),
            _raw(r"C:\Windows\notepad.exe.FriendlyAppName", "Notepad"),
            _raw(r"C:\Windows\notepad.exe.ApplicationCompany", "Microsoft Corporation"),
        ]
        grouped = group_muicache_values(raw)

        assert [g["path"] for g in grouped] == [
            r"E:\Tor Browser\Browser\firefox.exe",
            r"C:\Windows\notepad.exe",
        ]

    def test_empty_input_returns_empty_list(self):
        assert group_muicache_values([]) == []
