"""One test per interpretation rule in modules/module_a_registry/narrative.py, plus one
end-to-end test reproducing the exact reported scenario (installer download -> focus ->
install location -> linked launch)."""

from __future__ import annotations

from modules.module_a_registry.narrative import (
    build_key_finding,
    build_narrative,
    describe_download_source,
    describe_evidence_strength,
    describe_focus_duration,
    describe_install_date,
    describe_install_date_plain,
    describe_install_location,
    describe_last_use_summary,
    describe_no_findings,
    describe_not_determined,
    describe_reliability,
    describe_run0_with_focus,
    describe_source_time_gap,
    describe_user_account,
    describe_user_account_plain,
    format_dual_time,
    format_dual_time_plain,
    parse_tor_installer_filename,
)


class TestDescribeDownloadSource:
    def test_edge_download_staging_folder(self):
        path = r"C:\Users\Admin\AppData\Local\Temp\MicrosoftEdgeDownloads\g\tor-browser.exe"
        assert describe_download_source(path) == "Microsoft Edge"

    def test_chrome_user_data(self):
        path = r"C:\Users\bob\AppData\Local\Google\Chrome\User Data\Default\tor-browser.exe"
        assert describe_download_source(path) == "Google Chrome"

    def test_firefox_profile(self):
        path = r"C:\Users\bob\AppData\Roaming\Mozilla\Firefox\Profiles\x\tor-browser.exe"
        assert describe_download_source(path) == "Mozilla Firefox"

    def test_plain_downloads_folder(self):
        path = r"C:\Users\bob\Downloads\tor-browser.exe"
        assert describe_download_source(path) == "the user's Downloads folder"

    def test_unrecognized_path_returns_none_rather_than_guessing(self):
        assert describe_download_source(r"E:\Tor Browser\Browser\firefox.exe") is None

    def test_none_path(self):
        assert describe_download_source(None) is None


class TestParseTorInstallerFilename:
    def test_portable_x64_filename(self):
        info = parse_tor_installer_filename(
            r"C:\Users\x\Downloads\tor-browser-windows-x86_64-portable-15.0.21.exe"
        )
        assert info == {"version": "15.0.21", "arch": "x86_64", "portable": True}

    def test_non_portable_filename(self):
        info = parse_tor_installer_filename("tor-browser-windows-x86_64-14.5.exe")
        assert info == {"version": "14.5", "arch": "x86_64", "portable": False}

    def test_non_installer_filename_returns_none(self):
        assert parse_tor_installer_filename(r"E:\Tor Browser\Browser\firefox.exe") is None

    def test_none_path(self):
        assert parse_tor_installer_filename(None) is None


class TestDescribeFocusDuration:
    def test_rounds_to_whole_seconds(self):
        assert describe_focus_duration(47657) == "in front of the user for about 48 seconds"

    def test_singular_second(self):
        assert describe_focus_duration(1000) == "in front of the user for about 1 second"

    def test_zero_or_none_returns_none(self):
        assert describe_focus_duration(0) is None
        assert describe_focus_duration(None) is None

    def test_focus_count_over_one_is_phrased_as_a_running_total(self):
        # Real follow-up bug: total_focus_time_ms (like run_counter) is cumulative across
        # UserAssist's whole history for that component, not a single-visit duration --
        # wording must not imply "this one time" once focus_count shows it's a sum.
        result = describe_focus_duration(47657, 2)
        assert result == (
            "visible on screen for about 48 seconds in total, across 2 separate occasions"
        )

    def test_focus_count_of_one_or_none_is_phrased_as_a_single_occasion(self):
        assert describe_focus_duration(47657, 1) == "in front of the user for about 48 seconds"
        assert describe_focus_duration(47657, None) == "in front of the user for about 48 seconds"


class TestDescribeRun0WithFocus:
    def test_wording_mentions_not_a_completed_launch(self):
        text = describe_run0_with_focus("setup.exe", "in front of the user for about 5 seconds")
        assert "setup.exe" in text
        assert "not" in text and "completed launch" in text


class TestDescribeInstallLocation:
    def test_non_c_drive_gets_a_caveat(self):
        folder, note = describe_install_location(r"E:\Tor Browser\Browser\firefox.exe")
        assert folder == r"E:\Tor Browser\Browser"
        assert note is not None
        assert "E:" in note and "not the main system drive" in note

    def test_c_drive_has_no_caveat(self):
        folder, note = describe_install_location(r"C:\Tor Browser\Browser\firefox.exe")
        assert folder == r"C:\Tor Browser\Browser"
        assert note is None

    def test_none_path(self):
        assert describe_install_location(None) == (None, None)


class TestDescribeUserAccount:
    def test_found_in_a_findings_path(self):
        paths = [r"E:\Tor Browser\Browser\firefox.exe", r"C:\Users\Admin\Downloads\x.exe"]
        assert (
            describe_user_account(paths)
            == 'This activity belongs to the Windows user account "Admin".'
        )

    def test_not_found_states_so_plainly(self):
        paths = [r"E:\Tor Browser\Browser\firefox.exe"]
        result = describe_user_account(paths)
        assert "could not be determined" in result

    def test_bam_sid_resolved_via_profilelist_is_preferred_over_path_guess(self):
        # Paths alone would guess "Bob" (a \Users\<name>\ substring) -- the BAM SID,
        # resolved through ProfileList, is the authoritative source and must win.
        paths = [r"C:\Users\Bob\Downloads\x.exe"]
        profiles = [{"sid": "S-1-5-21-1-2-3-1001", "path": r"C:\Users\Admin"}]
        result = describe_user_account(paths, "S-1-5-21-1-2-3-1001", profiles)
        assert 'account "Admin"' in result
        assert "resolved via BAM + ProfileList" in result

    def test_falls_back_to_path_guess_when_sid_not_in_profiles(self):
        paths = [r"C:\Users\Bob\Downloads\x.exe"]
        profiles = [{"sid": "S-1-5-18", "path": r"C:\Windows\ServiceProfiles\LocalService"}]
        result = describe_user_account(paths, "S-1-5-21-unknown", profiles)
        assert 'account "Bob"' in result

    def test_falls_back_to_path_guess_when_no_sid_given(self):
        paths = [r"C:\Users\Bob\Downloads\x.exe"]
        result = describe_user_account(paths, None, [])
        assert 'account "Bob"' in result


class TestDescribeEvidenceStrength:
    def test_single_source(self):
        timeline = [{"basename": "firefox.exe", "seen_in": ["UserAssist"]}]
        text = describe_evidence_strength(timeline)
        assert "one source only (UserAssist)" in text
        assert "not confirmed by a second" in text

    def test_corroborated_by_two_or_more(self):
        timeline = [{"basename": "firefox.exe", "seen_in": ["Amcache", "UserAssist"]}]
        text = describe_evidence_strength(timeline)
        assert "confirmed by 2 independent sources" in text

    def test_no_components_at_all(self):
        assert (
            describe_evidence_strength([])
            == "Strength: no corroborating registry evidence was found."
        )


class TestDescribeNoFindings:
    def test_two_sentences_one_does_not_overclaim(self):
        lines = describe_no_findings()
        assert len(lines) == 2
        assert "No registry evidence" in lines[0]
        assert "does not prove" in lines[1]


class TestDescribeInstallDate:
    def test_with_amcache_timestamp(self):
        result = describe_install_date("2026-09-01T12:00:00+00:00", True, "Asia/Colombo")
        assert "first recorded by Windows on" in result
        assert "1 Sep 2026" in result

    def test_without_amcache_but_installer_seen_explains_why(self):
        result = describe_install_date(None, True, None)
        assert "installer's own UserAssist entry has no recorded run time" in result
        assert "Amcache" in result

    def test_without_amcache_timestamp_and_no_installer_seen_states_so_plainly(self):
        result = describe_install_date(None, False, None)
        assert result == (
            "The exact installation date could not be determined from the available "
            "registry data."
        )


class TestFormatDualTime:
    def test_with_resolved_timezone(self):
        result = format_dual_time("2026-09-03T04:41:53.211000+00:00", "Asia/Colombo")
        assert result == "3 Sep 2026 at 04:41:53 UTC (10:11 AM Asia/Colombo)"

    def test_without_timezone_is_utc_only(self):
        result = format_dual_time("2026-09-03T04:41:53+00:00", None)
        assert result == "3 Sep 2026 at 04:41:53 UTC"

    def test_unknown_zone_name_falls_back_to_utc_only(self):
        result = format_dual_time("2026-09-03T04:41:53+00:00", "Not/AZone")
        assert result == "3 Sep 2026 at 04:41:53 UTC"


class TestBuildNarrativeEndToEnd:
    def test_reported_scenario_matches_expected_story_with_no_amcache(self):
        # Mirrors the exact case that was reported: installer (run_count=0, focus
        # present, epoch-zero timestamp already cleaned to None upstream), a .lnk
        # shortcut and firefox.exe sharing one timestamp (linked launch), and no
        # Amcache entry at all (so no install date can be given).
        annotated_by_type = {
            "UserAssist": [
                {
                    "path": (
                        r"C:\Users\Admin\AppData\Local\Temp\MicrosoftEdgeDownloads\g\\"
                        r"tor-browser-windows-x86_64-portable-15.0.21.exe"
                    ),
                    "timestamp": None,
                    "run_count": 0,
                    "focus_count": 1,
                    "total_focus_time_ms": 47657,
                },
                {
                    "path": r"E:\Tor Browser\Tor Browser.lnk",
                    "timestamp": "2026-09-03T04:41:53.211000+00:00",
                    "run_count": 1,
                    "focus_count": 0,
                    "total_focus_time_ms": 1,
                },
                {
                    "path": r"E:\Tor Browser\Browser\firefox.exe",
                    "timestamp": "2026-09-03T04:41:53.211000+00:00",
                    "run_count": 1,
                    "focus_count": 0,
                    "total_focus_time_ms": 0,
                },
            ]
        }
        component_timeline = [
            {"basename": "firefox.exe", "seen_in": ["UserAssist"]},
            {"basename": "tor browser.lnk", "seen_in": ["UserAssist"]},
            {
                "basename": "tor-browser-windows-x86_64-portable-15.0.21.exe",
                "seen_in": ["UserAssist"],
            },
        ]
        linked_launches = [
            {
                "timestamp": "2026-09-03T04:41:53.211000+00:00",
                "paths": [
                    r"E:\Tor Browser\Browser\firefox.exe",
                    r"E:\Tor Browser\Tor Browser.lnk",
                ],
            }
        ]

        result = build_narrative(
            annotated_by_type, component_timeline, linked_launches, [], [], "Asia/Colombo"
        )

        assert result["timeline"] == [
            (
                "The Tor Browser 15.0.21 portable installer was downloaded and opened "
                "through Microsoft Edge."
            ),
            (
                "The installer window was in front of the user for about 48 seconds, "
                "consistent with clicking through the setup."
            ),
            (
                "Tor Browser was set up in E:\\Tor Browser. E: is not the main system "
                "drive and may be a USB drive or a second disk — files there may not "
                "remain on this machine."
            ),
            (
                "The exact date it was set up is not recorded, but it was before "
                "3 Sep 2026, 10:11 AM (04:41 UTC)."
            ),
            (
                "Tor Browser was opened once, on 3 Sep 2026, 10:11 AM (04:41 UTC), "
                "using its shortcut."
            ),
        ]
        assert 'the Windows account "Admin"' in result["key_finding"]
        assert "No." not in result["key_finding"]
        assert result["technical"]["account"] == (
            'This activity belongs to the Windows user account "Admin".'
        )
        assert "one source only (UserAssist)" in result["technical"]["strength"]
        assert "UserAssist" in result["technical"]["install_date_detail"]

    def test_revisited_installer_focus_time_is_phrased_as_a_running_total(self):
        # Real follow-up bug: the installer window's focus time is cumulative, just like
        # run_counter -- a user revisiting the installer window a second time (briefly)
        # bumps focus_count to 2, and the OLD, longer total_focus_time_ms from the first
        # visit still dominates the sum. Wording must not claim this one figure describes
        # "the last time" it was open.
        annotated_by_type = {
            "UserAssist": [
                {
                    "path": (
                        r"C:\Users\Admin\AppData\Local\Temp\MicrosoftEdgeDownloads\g\\"
                        r"tor-browser-windows-x86_64-portable-15.0.21.exe"
                    ),
                    "timestamp": None,
                    "run_count": 0,
                    "focus_count": 2,
                    "total_focus_time_ms": 47657,
                },
            ],
            "Amcache": [],
        }
        component_timeline = [
            {
                "basename": "tor-browser-windows-x86_64-portable-15.0.21.exe",
                "seen_in": ["UserAssist"],
            },
        ]

        result = build_narrative(annotated_by_type, component_timeline, [], [], [], None)

        assert (
            "The installer window was visible on screen for about 48 seconds in total, "
            "across 2 separate occasions — this is a running total Windows keeps for "
            "this program, not a single-visit duration, so it may be longer than just "
            "the most recent time it was open."
        ) in result["timeline"]
        assert not any(
            "consistent with clicking through the setup" in p for p in result["timeline"]
        )

    def test_second_launch_reports_true_run_count_not_distinct_timestamps(self):
        # Real follow-up bug: UserAssist overwrites its single timestamp field on every
        # run and only keeps a cumulative run_counter -- opening Tor Browser a second
        # time bumps firefox.exe and the .lnk to run_count=2 each, but there is only
        # ONE timestamp in the data (the latest). Counting distinct timestamps wrongly
        # says "1"; the fix must report the true run_counter-based count instead.
        annotated_by_type = {
            "UserAssist": [
                {
                    "path": r"E:\Tor Browser\Tor Browser.lnk",
                    "timestamp": "2026-10-04T07:30:42+00:00",
                    "run_count": 2,
                    "focus_count": 0,
                    "total_focus_time_ms": 0,
                },
                {
                    "path": r"E:\Tor Browser\Browser\firefox.exe",
                    "timestamp": "2026-10-04T07:30:42+00:00",
                    "run_count": 2,
                    "focus_count": 0,
                    "total_focus_time_ms": 0,
                },
            ],
            "Amcache": [],
        }
        component_timeline = [
            {"basename": "firefox.exe", "seen_in": ["UserAssist"]},
            {"basename": "tor browser.lnk", "seen_in": ["UserAssist"]},
        ]
        linked_launches = [
            {
                "timestamp": "2026-10-04T07:30:42+00:00",
                "paths": [
                    r"E:\Tor Browser\Browser\firefox.exe",
                    r"E:\Tor Browser\Tor Browser.lnk",
                ],
            }
        ]

        result = build_narrative(
            annotated_by_type, component_timeline, linked_launches, [], [], None
        )

        assert (
            "Tor Browser was opened 2 times; the dates of earlier uses were not "
            "recorded, but the most recent was on 4 Oct 2026, 07:30 UTC, using its "
            "shortcut."
        ) in result["timeline"]
        assert not any("opened once" in point for point in result["timeline"])
        assert not any("UserAssist" in point for point in result["timeline"])

    def test_empty_component_timeline_gives_no_findings_message(self):
        result = build_narrative({}, [], [], [], [], None)
        assert result["empty"] == describe_no_findings()
        assert result["timeline"] == []

    def test_no_technical_terms_in_key_finding_or_timeline(self):
        # Part 1 rule: "What happened"/"Key finding" must read as plain English -- no
        # registry artifact name, hive, SID, run-count, or "focus" wording anywhere.
        # Reuses the standard end-to-end fixture, which exercises every sentence type
        # (installer, focus-time, install location, install date, launch count).
        annotated_by_type = {
            "UserAssist": [
                {
                    "path": (
                        r"C:\Users\Admin\AppData\Local\Temp\MicrosoftEdgeDownloads\g"
                        "\\tor-browser-windows-x86_64-portable-15.0.21.exe"
                    ),
                    "timestamp": None,
                    "run_count": 0,
                    "focus_count": 2,
                    "total_focus_time_ms": 47657,
                },
                {
                    "path": r"E:\Tor Browser\Tor Browser.lnk",
                    "timestamp": "2026-09-03T04:41:53.211000+00:00",
                    "run_count": 2,
                    "focus_count": 0,
                    "total_focus_time_ms": 1,
                },
                {
                    "path": r"E:\Tor Browser\Browser\firefox.exe",
                    "timestamp": "2026-09-03T04:41:53.211000+00:00",
                    "run_count": 2,
                    "focus_count": 0,
                    "total_focus_time_ms": 0,
                },
            ],
            "BAM": [
                {
                    "path": r"E:\Tor Browser\Browser\firefox.exe",
                    "timestamp": "2026-09-03T04:41:58+00:00",
                    "sid": "S-1-5-21-1-2-3-1001",
                }
            ],
        }
        component_timeline = [
            {
                "basename": "firefox.exe",
                "seen_in": ["UserAssist", "BAM"],
                "userassist_last_run": _dt("2026-09-03T04:41:53.211000+00:00"),
                "bam_last_run": _dt("2026-09-03T04:41:58+00:00"),
            },
            {"basename": "tor browser.lnk", "seen_in": ["UserAssist"]},
            {
                "basename": "tor-browser-windows-x86_64-portable-15.0.21.exe",
                "seen_in": ["UserAssist"],
            },
        ]
        linked_launches = [
            {
                "timestamp": "2026-09-03T04:41:53.211000+00:00",
                "paths": [
                    r"E:\Tor Browser\Browser\firefox.exe",
                    r"E:\Tor Browser\Tor Browser.lnk",
                ],
            }
        ]

        result = build_narrative(
            annotated_by_type, component_timeline, linked_launches, [], [], "Asia/Colombo"
        )

        banned = [
            "UserAssist",
            "BAM",
            "Amcache",
            "ShimCache",
            " hive",
            "SID",
            "run_count",
            "run count",
            "focus",
        ]
        plain_text = result["key_finding"] + " ".join(result["timeline"])
        for term in banned:
            assert term.lower() not in plain_text.lower(), f"{term!r} leaked into: {plain_text!r}"


def _dt(iso: str):
    from datetime import datetime

    return datetime.fromisoformat(iso)


class TestDescribeReliability:
    def test_no_components_gives_nothing_to_rate(self):
        assert describe_reliability([]) == [
            "No Windows record of this activity was found, so there is nothing to rate here."
        ]

    def test_single_source_is_solid_but_not_strong(self):
        timeline = [{"basename": "firefox.exe", "seen_in": ["UserAssist"]}]
        lines = describe_reliability(timeline)
        assert "Only one Windows record" in lines[0]
        assert "UserAssist" not in lines[0]

    def test_two_sources_is_phrased_as_strong_without_naming_them(self):
        timeline = [{"basename": "firefox.exe", "seen_in": ["UserAssist", "BAM"]}]
        lines = describe_reliability(timeline)
        assert "Two separate Windows features" in lines[0]
        assert "strong evidence" in lines[0]
        assert "UserAssist" not in lines[0] and "BAM" not in lines[0]

    def test_always_includes_a_generic_missing_record_sentence(self):
        timeline = [{"basename": "firefox.exe", "seen_in": ["UserAssist"]}]
        lines = describe_reliability(timeline)
        assert len(lines) == 2
        assert "periodic scan" in lines[1]


class TestDescribeNotDetermined:
    def test_no_install_timestamp_flags_it(self):
        bullets = describe_not_determined(None, multiple_launches=False)
        assert "exact date Tor Browser was set up" in bullets[0]

    def test_known_install_timestamp_omits_that_bullet(self):
        bullets = describe_not_determined("2026-09-01T00:00:00+00:00", multiple_launches=False)
        assert not any("set up" in b for b in bullets)

    def test_multiple_launches_flags_earlier_use_dates_unknown(self):
        bullets = describe_not_determined(None, multiple_launches=True)
        assert any("dates of earlier uses" in b for b in bullets)

    def test_always_points_to_modules_b_and_c_for_browsing_content(self):
        bullets = describe_not_determined("2026-09-01T00:00:00+00:00", multiple_launches=False)
        assert any("disk and memory sections" in b for b in bullets)


class TestBuildKeyFinding:
    def test_no_findings_says_no_plainly(self):
        result = build_key_finding(False, 'the Windows account "Admin"', 0, None, None)
        assert result.startswith("No.")

    def test_single_launch_is_phrased_as_once(self):
        result = build_key_finding(
            True, 'the Windows account "Admin"', 1, "2026-10-04T13:00:00+00:00", "Asia/Colombo"
        )
        assert "opened once" in result
        assert 'the Windows account "Admin"' in result
        assert "4 Oct 2026" in result

    def test_multiple_launches_includes_the_count(self):
        result = build_key_finding(
            True, 'the Windows account "Admin"', 2, "2026-10-04T13:00:00+00:00", None
        )
        assert "opened 2 times" in result

    def test_findings_without_a_completed_launch_is_phrased_as_likely(self):
        result = build_key_finding(True, 'the Windows account "Admin"', 0, None, None)
        assert result.startswith("Likely.")
        assert "no completed launch was recorded" in result


class TestDescribeUserAccountPlain:
    def test_resolved_username_has_no_sid_or_bam_mention(self):
        paths = [r"C:\Users\Bob\Downloads\x.exe"]
        result = describe_user_account_plain(paths)
        assert result == 'the Windows account "Bob"'

    def test_unresolved_is_a_plain_noun_phrase(self):
        assert describe_user_account_plain([]) == "an unidentified Windows account"


class TestDescribeInstallDatePlain:
    def test_known_install_timestamp(self):
        result = describe_install_date_plain("2026-09-01T12:00:00+00:00", None, "Asia/Colombo")
        assert result == "Tor Browser was set up on 1 Sep 2026, 5:30 PM (12:00 UTC)."

    def test_unknown_install_but_known_earliest_use(self):
        result = describe_install_date_plain(None, "2026-09-03T04:41:53+00:00", "Asia/Colombo")
        assert result == (
            "The exact date it was set up is not recorded, but it was before "
            "3 Sep 2026, 10:11 AM (04:41 UTC)."
        )
        assert "Amcache" not in result
        assert "UserAssist" not in result

    def test_nothing_known(self):
        assert describe_install_date_plain(None, None, None) == (
            "The exact date it was set up is not recorded."
        )


class TestFormatDualTimePlain:
    def test_local_leads_utc_trails_in_brackets(self):
        assert format_dual_time_plain("2026-10-04T07:30:00+00:00", "Asia/Colombo") == (
            "4 Oct 2026, 1:00 PM (07:30 UTC)"
        )

    def test_no_timezone_is_utc_only_24h(self):
        assert format_dual_time_plain("2026-10-04T07:30:00+00:00", None) == (
            "4 Oct 2026, 07:30 UTC"
        )

    def test_unknown_zone_falls_back_to_utc_only(self):
        assert format_dual_time_plain("2026-10-04T07:30:00+00:00", "Not/AZone") == (
            "4 Oct 2026, 07:30 UTC"
        )


class TestDescribeSourceTimeGap:
    def test_gap_is_explained_once_with_both_timestamps(self):
        component = {
            "userassist_last_run": _dt("2026-10-04T07:30:42+00:00"),
            "bam_last_run": _dt("2026-10-04T07:31:01+00:00"),
        }
        result = describe_source_time_gap(component, None)
        assert "UserAssist recorded this at" in result
        assert "BAM recorded it at" in result
        assert "gap of 19 seconds" in result
        assert "same use" in result

    def test_identical_timestamps_need_no_explanation(self):
        component = {
            "userassist_last_run": _dt("2026-10-04T07:30:42+00:00"),
            "bam_last_run": _dt("2026-10-04T07:30:42+00:00"),
        }
        assert describe_source_time_gap(component, None) is None

    def test_missing_one_source_needs_no_explanation(self):
        component = {"userassist_last_run": _dt("2026-10-04T07:30:42+00:00"), "bam_last_run": None}
        assert describe_source_time_gap(component, None) is None


class TestDescribeLastUseSummary:
    def test_picks_the_later_of_the_two_and_names_its_source(self):
        component = {
            "userassist_last_run": _dt("2026-10-04T07:30:42+00:00"),
            "bam_last_run": _dt("2026-10-04T07:31:01+00:00"),
        }
        result = describe_last_use_summary(component, None)
        assert "recorded by BAM" in result

    def test_none_when_neither_source_present(self):
        assert describe_last_use_summary({}, None) is None
