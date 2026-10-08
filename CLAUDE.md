# CLAUDE.md — TRANCE handoff

TRANCE is a forensic triage tool for Tor Browser activity on Windows 10/11 (CS3400 Cyber
Security coursework, team project). It **acquires** evidence from a live Windows target and
**analyzes** it offline across three layers — registry (Module A), disk (Module B), memory
(Module C) — then merges everything into one `findings.json` and renders one HTML report.

This file is the current source of truth for how the system fits together. `context.md` is an
older, Module-C-only progress log (useful history, but parts are stale — e.g. it says Modules
A/B are stubs; they are not). `README.md` is the user-facing doc and also has stale sections
(see "Known stale docs" below).

---

## 1. Big picture: acquire vs. analyze

The whole design rests on one split. Keep it.

| | Acquire side | Analyze side |
|---|---|---|
| Runs on | the **target** Windows machine, elevated | the **examiner's** machine (any OS) |
| Entry point | `acquire_all.py` → `trance-acquire.exe` | `main.py` (CLI), `analyze_evidence.py` (folder wrapper), `gui_main.py` (desktop app) |
| Platform code | Windows-only (`ctypes.windll`, `reg save`, WMI/VSS, WinPMEM) | cross-platform, pure Python + regipy/jinja2/lz4 |
| Heavy deps | none beyond `psutil` | regipy, jinja2, lz4; PySide6 for GUI; Volatility3 only as an external `vol` CLI |
| Output | an evidence folder + `acquire_manifest.json` | `<output-dir>/<case>/findings.json`, `report.html`, `custody.json` |

Rationale (don't undo this): minimal footprint on the evidence machine, and heavy analysis
deps never touch the target. Every acquisition step hashes its output, writes a `.sha256`
sidecar and a chain-of-custody JSON (`core/custody_log.py`).

```
target (Windows, admin)                         examiner machine
┌──────────────────────────┐   copy folder    ┌─────────────────────────────────────────┐
│ trance-acquire.exe       │ ───────────────▶ │ analyze_evidence.py / GUI                │
│  registry/ memory/ disk/ │                  │   resolve_evidence(folder)               │
│  acquire_manifest.json   │                  │     → main.run_pipeline(config, kwargs)  │
└──────────────────────────┘                  │       → module_a/b/c.run() each          │
                                              │       → findings.json → report.html      │
                                              └─────────────────────────────────────────┘
```

---

## 2. Repo layout

```
acquire_all.py            target-side orchestrator (registry + memory + disk) → evidence folder
analyze_evidence.py       examiner-side wrapper: evidence folder → argv → main.main()
main.py                   the pipeline: run_pipeline() + CLI main()
findings.py               merges ModuleResults into findings.json (schema_version 1)
report.py                 renders findings.json → report.html via PRESENTERS + Jinja2
report_template.html.j2   the HTML report (~1000 lines, dark/light CSS tokens)
gui_main.py               PySide6 desktop app entry point
gui/                      desktop app (see §6)
core/                     shared: config, schema, custody_log, hashing, exceptions,
                          winadmin (is_admin), fs_scan (auto-discovery walker)
modules/module_a_registry/  Module A
modules/module_b_disk/      Module B
modules/module_c_memory/    Module C
tests/                    pytest suite (~210 tests)
output/                   local case outputs (gitignored) — some are STALE, see §8
.github/workflows/ci.yml  pytest + ruff + black on push/PR to main/dev
```

Requirements are split on purpose:
- `requirements.txt` — analysis deps (`regipy`, `jinja2`, `lz4`, `psutil`, `click`, plus
  `volatility3` and `yara-python`, see §8 on those two).
- `requirements-dev.txt` — pytest, pytest-cov, mypy, ruff, black.
- `requirements-gui.txt` — `PySide6` only. Kept separate so the CLI exes stay lean.

Style: black + ruff, line length 100, target py310 (`pyproject.toml`). Several ruff rules are
intentionally ignored with written justification in `pyproject.toml` — read it before
"fixing" them.

---

## 3. Core contracts

**Module contract** (`README.md` → "Module contract"):
```python
modules/<name>/__init__.py:
    def run(config: core.config.TranceConfig, **kwargs) -> core.schema.ModuleResult
```
- `ModuleResult(module, status, artifacts, details, message)`; `status` ∈
  `ok | partial | skipped | not_implemented | error` (`core.schema.MODULE_STATUSES`).
  `partial` means one or more individual extractors/sub-steps failed but the module still
  produced real findings — see "Per-extractor isolation" below; `error` is reserved for a
  whole-module failure (e.g. an integrity-hash mismatch).
- `artifacts`: flat list of `core.schema.Artifact(module, artifact_type, source, description,
  sha256, timestamp, confidence, confidence_reason, category)` — goes into
  `findings.json["artifacts"]` for every module. The last three fields are Module A-specific
  (`"high"/"medium"/"low"`, a one-line reason, `"tor-direct"/"context"`); Modules B/C leave
  them `None`.
- `details`: arbitrary module-specific dict kept verbatim under
  `findings.json["modules"][name]["details"]` — this is what the report presenters read.
  By convention `details["warnings"]` is a list of `{"artifact_type", "source", "reason",
  "traceback"}` dicts for any sub-step that failed without failing the whole module (see
  below); the root report.py and `report_template.html.j2` render these as a plain-English
  "could not be read" callout rather than hiding the rest of that module's findings.
- Heavy analysis imports are done **lazily inside `run()`** so the acquire scripts living in
  the same package stay importable without regipy etc. Keep it that way.
- A module that raises an exception it never catches itself is caught by
  `main.run_module()` and recorded as `error`; it never stops the other modules. Modules
  A/B additionally isolate failures **inside** themselves, per extractor/sub-step, so one
  bad artifact type degrades to `partial` with a warning instead of failing the whole
  module (Module C's single linear `analyze()` pass has no per-step seams of its own; its
  `run()` only hardens the outer boundary — `except Exception`, not just its own
  `TranceError` subclasses — so an unexpected exception still degrades to a clean `error`
  result rather than propagating).

**Pipeline** (`main.py`):
- `run_pipeline(config, module_kwargs, progress_cb=None) -> PipelineResult` runs
  `MODULES = ("module_a_registry", "module_b_disk", "module_c_memory")` in order, builds
  findings, writes `findings.json` + `report.html`, builds and writes `custody.json`.
  `progress_cb(step_name, step, total)` fires after each module and once after writing
  outputs (total = 4). Used by the GUI.
- `main(argv)` is the CLI: argparse + validation (case name must be a single path
  component; outputs must not already exist; output dir must be outside disk evidence),
  builds `module_kwargs`, calls `run_pipeline`. Exit code 2 if any module errored.
- Modules are imported via `importlib.import_module(f"modules.{name}")` — PyInstaller cannot
  see that, hence the `--hidden-import` flags in the build commands (§7).

**Report** (`report.py`): `PRESENTERS = {module_name: build_context}` from each module's own
`report.py`. A module with status `ok` and a presenter gets a dedicated section; otherwise a
generic artifact table (capped at 200 rows). Everything is deterministic, offline, no LLM.

---

## 4. The three modules

### Module A — registry & execution evidence (`modules/module_a_registry/`)

Module A is mid-way through a multi-phase roadmap: Phase 0 "foundations", Phase 1
"execution evidence", Phase 2 "device evidence" (USB/MountedDevices/MountPoints2/
EMDMgmt/Windows Portable Devices, plus a direct drive-letter → physical-device
correlation), Phase 3 "network context" (NetworkList/Tcpip), Phase 4 "persistence and
configuration" (Run/RunOnce, services, Internet Settings proxy), and Phase 5 "report
integration" for all of the above are done; Phase 6 (SRUM/event logs) is not started.
What follows describes the current state.

- **Acquire** (`acquire.py`, Windows, admin): `reg save HKLM\SYSTEM`, `reg save
  HKLM\SOFTWARE`, and `reg save HKCU` (current user's NTUSER.DAT); Amcache.hve via a
  Volume Shadow Copy created with WMI (`Win32_ShadowCopy.Create()` through PowerShell —
  `vssadmin create shadow` is Server-only, confirmed on real client Windows) and deleted
  with `vssadmin delete shadows` afterwards. `--ntuser-user <name>` pulls another user's
  NTUSER.DAT via VSS instead of the live HKCU export. UsrClass.dat is acquired the same
  way (VSS copy, no live-registry variant — see `acquire_usrclass()`'s docstring) for
  that same target user (or the current session's username if `--ntuser-user` wasn't
  given). Each hive/flag independent; `--skip-usrclass` etc. opt out.
- **Analyze** (`pipeline.py`): hash on ingest → extraction (each extractor isolated in its
  own try/except inside `_process_hive()` — see "Per-extractor isolation" in §3) →
  Tor-relevance filter (`constants.py: is_tor_related_entry`) → normalize to `Artifact`s
  (`normalize.py`) → re-hash and raise `IntegrityError` on mismatch. 30 artifact types
  total, from three sources (plus one bypassed-plugin reimplementation, see below):
  - **regipy plugins, thin-wrapped in `extractors.py`**: UserAssist, RecentDocs, MUICache,
    RunMRU, WordWheelQuery, ComDlg32, TypedPaths from NTUSER; ShimCache, BAM, ComputerName,
    TimeZone, USBSTOR, generic USB devices, MountedDevices, Windows Portable Devices (WPD,
    resolved per-ControlSet via `get_control_sets()`, same as ComputerName/TimeZone),
    network interfaces (Tcpip, Phase 3) from SYSTEM; Amcache; InstalledPrograms,
    WindowsVersion from SOFTWARE; ShellBags from UsrClass.dat (needs the `regipy[full]`
    extra — `libfwsi-python`/`libfwps-python`, importable as `pyfwsi`/`pyfwps` — see
    requirements.txt). ShellBags extraction is
    additionally patched (`_shellbags_patch.py`, applied via `apply_shellbags_patch()`):
    `pyfwsi`'s `get_creation_time()`/`get_access_time()` can raise a bare `SystemError`
    ("invalid format string: %hhu.") on certain real entries that regipy's own
    `except OSError:` doesn't catch, aborting the *entire* hive's ShellBags extraction over
    one bad timestamp — confirmed by reproducing it against a real UsrClass.dat, not
    guessed. The patch widens that to `except (OSError, SystemError):` and additionally
    isolates each MRU slot in its own try/except (`plugin._shellbags_skip_count` tracks how
    many were skipped) so one malformed entry degrades gracefully instead of losing the
    whole hive; applying it twice is a no-op (idempotent).
  - **One regipy *function* reused directly, bypassing a broken plugin *method* for this
    one sub-case** (`extract_last_visited_pidl_mru` in `extractors.py`): ComDlg32Plugin's
    own `LastVisitedPidlMRU` handling reuses OpenSavePidlMRU's "value names are
    digit-indexed MRU slots" assumption, but LastVisitedPidlMRU's real values are named
    for the *invoking program's full path* with no digit-named values at all — that
    method silently returns zero entries against a real hive. Reimplemented correctly
    using regipy's own public `parse_pidl_mru_value()` + `LAST_VISITED_PIDL_MRU_PATH`;
    OpenSavePidlMRU/OpenSaveMRU (same plugin, unaffected) are still used as-is.
  - **Hand-written parsers, no regipy plugin exists at all — `custom_extractors.py`**:
    MUICache from UsrClass.dat (a same-named NTUSER-only plugin exists but can never
    reach this data — see that file's module docstring), Program Compatibility Assistant
    Store, `Software\Mozilla\Firefox\Launcher`, `FeatureUsage\AppSwitched`, MountPoints2,
    Run/RunOnce (Phase 4), Internet Settings proxy config (Phase 4) all from NTUSER;
    EMDMgmt (ReadyBoost device-eligibility test records), Run/RunOnce (HKLM + WOW6432Node,
    Phase 4) from SOFTWARE; services (Phase 4) from SYSTEM. Every hive is opened with an
    **explicit** `hive_type=` (never regipy's own auto-detection, which reads the hive's
    *embedded* header path and is unreliable for an acquired/renamed copy — confirmed
    broken for UsrClass.dat specifically, whose check is an exact-equality match no real
    acquired hive will ever satisfy).
  - **A fourth source — a regipy plugin that exists but is bypassed and reimplemented
    using its own public helper functions**, same pattern as the `extract_mounted_devices()`/
    `extract_last_visited_pidl_mru()` precedent below: network profiles (NetworkList,
    Phase 3) from SOFTWARE, via `NetworkListPlugin`'s own `parse_network_date()`/
    `format_mac_address()` against real bytes (its own `run()` is broken the same
    `trim_values=True` way MountedDevicesPlugin was — see the Phase 3 writeup below).
  - MUICache-from-UsrClass deliberately shares the `MUICache` artifact type with the
    NTUSER-sourced one (same kind of evidence, two possible source hives depending on
    Windows version; merged into one report section, `Artifact.source` differentiates).
- **Filter philosophy**: deliberately *recall over precision* for every "tor-direct"
  type — substring path markers (`"tor browser"`, `"torbrowser"`, `"\\tbb\\"`,
  `"torproject"`, …) plus a list of Tor-specific executable names. `firefox.exe` alone is
  intentionally NOT a match. `is_tor_related_entry()` extends plain `is_tor_related()`
  for the one type that needs a second field checked: `LastVisitedPidlMRU`'s `program`
  field (the invoking exe's full path) can establish Tor-relevance even when its paired
  folder alone gives no hint (a Tor Browser Save-As dialog pointed at a plain Downloads
  folder) — `_ADDITIONAL_TOR_CHECK_FIELDS` in `constants.py` is where any future type
  needing the same treatment gets added.
- **Confidence / category — structured `Artifact` fields, not description prose**:
  `Artifact` has `confidence` (`"high"`/`"medium"`/`"low"`), `confidence_reason` (one-line
  justification), and `category` (`"tor-direct"`/`"context"`), all assigned once per
  `artifact_type` in `normalize.py` from `constants.py`'s `ARTIFACT_CONFIDENCE` /
  `ARTIFACT_CONFIDENCE_REASON` / `ARTIFACT_CATEGORY` maps — the single source of truth.
  Nine types are `category="context"`: Phase 0's ComputerName/TimeZone/WindowsVersion
  (machine-wide facts) plus Phase 2's USBStor (HIGH — authoritative USB mass-storage
  connection history), MountedDevices (HIGH — a direct drive-letter/volume-to-device
  mapping), USBDevices (MEDIUM — generic enumeration, not mass-storage-specific), EMDMgmt
  (MEDIUM — an independent ReadyBoost-eligibility test record, best-effort on exact value
  layout beyond the device-identifying subkey name), MountPoints2 and PortableDevices
  (LOW — "this volume/MTP device was seen at some point", contextual only). None of these
  nine are filtered by `is_tor_related()` (no USB device's own data ever says "Tor
  Browser"), and — per `pipeline.py`'s `run_module_a()` — **all are only kept in the final
  findings if the same run also produced at least one "tor-direct" finding** (a bare
  computer name or USB history isn't interesting on its own). `findings.json`'s
  per-module `artifacts` stay a superset across all modules; Module B/C artifacts simply
  leave these three fields `None`.
  Program Compatibility Assistant Store's and Firefox Launcher's value **data** (beyond
  the path-bearing value name) are decoded best-effort / low-confidence-on-exact-layout —
  neither has been verified against a real captured hive yet; treat
  `flagged_timestamp`/`raw_value` as supplementary, not authoritative, same caveat
  ComDlg32's own PIDL decoding and EMDMgmt's `device_capacity` already carry.
- **Report** (`report.py`): dedupes, builds a per-component cross-hive timeline
  (`_build_component_timeline()`), and counts components *corroborated by 2+ independent
  execution sources* — the only cross-hive correlation in the codebase, and only within
  Module A. `build_context()`'s `system_context` key carries Phase 0's three machine
  facts separately from the tor-direct `sections` list (structured only — no
  narrative/template prose; that's Phase 5).
  **`_build_component_timeline()` only ever iterates tor-direct findings**
  (`_is_tor_direct()`, reading each finding's own `category` field) — a real, confirmed
  bug that shipped with Phase 2 and was fixed afterward: widening `_PATH_RE` to also
  match `"device '...'"`/`"entry '...'"` gave every device-evidence type a `path` field
  too, and this function iterated every artifact_type unconditionally, so every USB
  device, drive letter and volume GUID on a real machine was being counted as a "Tor
  Browser component" (one real acquisition showed "58 distinct files" where only 8 were
  genuinely Tor-related). `narrative.py`'s account-resolution path scan got the same
  category guard defensively. The table's "N distinct files" count is just
  `component_timeline`'s length — fixing the filter fixed that count too, nothing else to
  maintain.
  Each component also carries `execution_sources` — the subset of `seen_in` in
  `EXECUTION_SOURCE_TYPES` (`UserAssist`/`Amcache`/`ShimCache`/`BAM`/`MUICache`) — used
  for the corroboration count and `narrative.py`'s "N independent sources confirm
  execution" claims instead of the broader `seen_in`: **ShellBags only ever shows a
  folder was browsed in Explorer, never that anything inside it was executed**, so it
  must not inflate that count (it still appears in `seen_in` and the table's "Seen in"
  chips, and still feeds its own plain-English timeline sentence — just not counted as
  execution corroboration). MUICache *is* in `EXECUTION_SOURCE_TYPES` — the shell actually
  invokes a program to populate it — even though its own timestamp (the key's shared
  last-write time, see below) is never used for timing.
  Also found and fixed while on this: regipy's own `MountedDevicesPlugin` never actually
  decodes anything, on any machine — `NKRecord.iter_values()` defaults to
  `trim_values=True`, which returns a **hex string**, not `bytes`, for `REG_BINARY` data
  (exactly what every `MountedDevices` value is), so the plugin's own
  `isinstance(data, bytes)` check is always `False` and its `parse_device_data()` call is
  never reached. `extractors.extract_mounted_devices()` no longer uses that plugin — it
  reimplements its short categorization logic directly, reading real bytes via
  `iter_values(trim_values=False)` and calling regipy's own public `parse_device_data()`
  itself (same "bypass the one broken piece, reuse the rest of the public API" precedent
  `extract_last_visited_pidl_mru()` already set for a different plugin). This also
  surfaced that Windows **Dynamic Disk** volumes store `"DMIO:ID:" + a 16-byte LDM object
  id` as their `MountedDevices` value — a shape `parse_device_data()` doesn't (and
  shouldn't) recognize; flagged as `entry["dynamic_disk"] = True` without attempting a
  decode. Windows does not support dynamic disks on removable USB media, so finding this
  on the Tor install's own drive is itself real, structural evidence it's an
  internal/fixed-disk partition, not a USB stick — see `devices` below.
  `devices` (built by `_build_device_correlation()`, modeled on `_build_profiles_table()`'s
  is-relevant-flagging pattern) resolves the Tor install's own drive letter (via
  `narrative.find_install_location_path()` + `extract_drive_letter()`, called *before*
  `build_narrative()` so the result can feed back into its sentences) through a chain,
  strongest first: (1) a Dynamic Disk identifier on that drive stops resolution right
  there (see above); (2) the decoded `MountedDevices` value directly names a
  USBSTOR-shaped path — join its serial against `USBStor`/`PortableDevices` (both embed
  the same serial; a real Phase 2 bug put PortableDevices in the "never matches" bucket,
  fixed); (3) the decoded value instead names a bare `\??\Volume{GUID}` — look for a
  *sibling* `MountedDevices` entry literally named that same `\??\Volume{GUID}` string
  and retry step 2 against it (exact value-name match only; USBSTOR's own `disk_guid`
  field was checked against real `MountedDevices` volume GUIDs and never matches, so no
  fuzzy/near-GUID matching was built — confirmed dead end, not merely unneeded); (4)
  nothing resolves — state so plainly and offer every `USBStor`/`PortableDevices` entry as
  a candidate (never `USBDevices` hubs/cameras/sensors, never `MountPoints2`/`EMDMgmt`).
  Nothing is discarded at any step: every device/volume the machine has ever recorded
  still renders in the "All connected devices and volumes" appendix, with only the
  matched row(s) flagged `is_relevant`. Verified end-to-end against a real evidence
  capture: that machine's `E:`/`C:`/`D:` are genuine Dynamic Disk volumes (confirmed via
  raw bytes) while its `F:`/`G:` decode cleanly to real USBSTOR paths — proving both the
  dynamic-disk branch and the decode path itself are sound, not just mocked.
- **Narrative** (`narrative.py`): deterministic, rule-based plain-English story
  (`key_finding`/`timeline`/`reliability`/`not_determined`/`device_story` for a
  non-technical reader, plus a `technical` sub-dict) — still doesn't reference Phase 0's
  three context facts.
  `describe_drive_device()` is the one shared function behind both
  `describe_install_location()`'s inline install-location caveat and the dedicated
  **"Where Tor Browser ran from"** section (`device_story`, new) — so the two can never
  disagree. Three cases: resolved (names the device, serial, and — `device_story` only,
  via `include_timing=True` — first/last-connected when USBSTOR provides them), Dynamic
  Disk (the "Windows does not allow dynamic disks on removable USB drives..." sentence),
  or unknown (the inline caveat keeps exactly its original pre-Phase-2 generic wording,
  regression-pinned; `device_story` instead states plainly the device couldn't be
  identified and lists candidates).
  ShellBags gets a plain-English timeline sentence too, chronologically interleaved with
  the launch sentence (both carry real timestamps; everything else in the timeline keeps
  its fixed logical position). Wording was deliberately checked against
  `ShellBagUsrclassPlugin.iter_sk()`'s own source first: a ShellBags entry's `timestamp`
  is the **BagMRU registry key's own last-write time**, shared by every slot under that
  key — not the folder's own filesystem access time (that field exists in the raw plugin
  data as `access_time`/`creation_time`/`modification_time` but was never surfaced past
  extraction, and still isn't). A key-write isn't guaranteed to mean "freshly visited at
  this exact instant", so the sentence says *"Explorer recorded the folder ... (last
  updated X)"*, not *"the user opened the folder ... on X"* — the stronger claim the data
  doesn't actually support.
- MUICache's Vista+ convention stores **two separate registry values per program**
  (`<path>.FriendlyAppName` / `<path>.ApplicationCompany`) — both `extract_muicache()`
  and `extract_muicache_usrclass()` used to treat each as its own finding, so one real
  program showed up as two fake "files" with the literal suffix stuck onto the basename.
  Both now call the new `_muicache_grouping.group_muicache_values()` before returning,
  merging the pair (or passing a bare pre-Vista single-value entry through unchanged) into
  one record; `normalize.py` renders both fields, e.g. `"... entry for
  'firefox.exe' — 'Tor Browser', Mozilla Corporation."`. MUICache's timestamp is also the
  registry key's own shared last-write time, not a per-program run time — the "Raw
  findings by hive" table labels that column "Registry key last updated" specifically for
  MUICache's rows, with a one-line caption saying so.
- **Phase 3 — network context.** `extractors.extract_network_profiles()` joins SOFTWARE's
  `NetworkList\Profiles` with `NetworkList\Signatures\{Managed,Unmanaged}` (on
  `ProfileGuid`), new `ARTIFACT_TYPE_NETWORK_PROFILE` (`CATEGORY_CONTEXT`, same "only kept
  alongside a tor-direct finding" gate as Phase 2's device types). Deliberately does NOT
  use regipy's own `NetworkListPlugin`, despite one existing: confirmed against a real
  SOFTWARE hive (59 real profiles) that its `run()` reads every value through
  `extract_values()`'s default `iter_values()` (`trim_values=True`), which returns a HEX
  STRING, not bytes, for `DateCreated`/`DateLastConnected`/`DefaultGatewayMac` (REG_BINARY)
  — the same bug class already fixed for `MountedDevicesPlugin`. Confirmed real-world
  effect: `date_created`/`date_last_connected` came back `None` for every one of 59 real
  profiles, and `default_gateway_mac` came back a raw hex string (`"e47deb7a4551"`)
  instead of a formatted MAC. Fixed the same way as `extract_mounted_devices()`: bypass
  the plugin's `run()`, reuse its own public `parse_network_date()`/`format_mac_address()`
  against real bytes read via `iter_values(trim_values=False)`. `DateCreated`/
  `DateLastConnected` decode to a **naive local-time** ISO string (confirmed by manually
  decoding a real SYSTEMTIME blob against the known acquisition date) — never promoted to
  `Artifact.timestamp` (which every other type treats as UTC); report.py converts to UTC
  explicitly via `narrative.local_systemtime_to_utc()` using the system's own recorded
  `TimeZoneInformation` Bias (`UTC = local + bias_minutes`, confirmed against this
  project's own real evidence: Sri Lanka Standard Time, UTC+5:30, recorded `Bias=-330`) —
  deliberately NOT the examiner's own `local_tz` display preference, a different concept
  (see `format_dual_time()`). `extractors.extract_network_interfaces()` thin-wraps
  regipy's `NetworkDataPlugin` (SYSTEM's `Services\Tcpip\Parameters\Interfaces`, resolved
  per existing ControlSet) — unlike NetworkListPlugin, this one works correctly against
  real evidence (DHCP lease times are Unix-epoch DWORDs, not FILETIME, and the plugin
  converts them correctly); its own recursive `sub_interface` field is dropped (confirmed
  against real data to be leftover WLAN-profile-shaped garbage, not real nested
  interfaces). `report.py`'s `_build_network_context()` resolves the Tor launch instant via
  `narrative.find_latest_tor_use_iso()` (same "second, independent call" precedent as
  `find_install_location_path()`) and produces the brief's required careful wording —
  *"The most recent network connection recorded before Tor Browser was last opened was to
  [SSID] (router [MAC]) at [time]"* — never "connected while using Tor"; plus same-day
  network-creation notes and DHCP-lease-covers-launch sentences
  (`narrative.build_network_narrative()`). When the system's time zone is unknown, no
  local→UTC comparison is attempted at all (profiles shown local-time-only, explicitly
  labeled, per the brief) — see `_TIMEZONE_UNKNOWN_CAVEAT`. **Found and fixed along the
  way** (blocking this phase, since it needs a working Bias value): `normalize.py`'s
  `_normalize_time_zone()`/`_normalize_windows_version()` read the wrong-cased field names
  (`time_zone_key_name`/`bias`/`product_name`/... vs. the real
  `TimeZoneKeyName`/`Bias`/`ProductName`/... regipy plugins actually return, confirmed
  against real hives) — every real report said *"Windows time zone configured as
  '\<unknown\>'."* and *"Windows version recorded as '\<unknown\>'."* since Phase 0; the
  hand-built test fixtures used the same wrong casing, which is why ~210 passing tests
  never caught it.
- **Phase 4 — persistence and configuration.** Three new `CATEGORY_TOR_DIRECT` types
  (unlike Phase 2/3's context types, only ever present at all once they reference Tor —
  Module A still never reports "every autostart entry"): `ARTIFACT_TYPE_RUNKEY`
  (`custom_extractors.extract_run_keys_ntuser/_software()` — HKCU Run/RunOnce plus HKLM
  Run/RunOnce/WOW6432Node, no regipy plugin exists), `ARTIFACT_TYPE_SERVICE`
  (`extract_services()`, SYSTEM's `Services`), `ARTIFACT_TYPE_PROXY_SETTINGS`
  (`extract_proxy_settings()`, NTUSER's Internet Settings). A shared
  `constants.extract_command_executable()` strips quoting/arguments from a Run value or a
  service's ImagePath before matching — confirmed real gap: a real ImagePath like
  `'"C:\...\RtkAudUService64.exe" -background'` would otherwise defeat
  `is_tor_related()`'s basename check entirely (it would extract `'...exe" -background'`,
  never matching `TOR_EXECUTABLE_NAMES`). `extract_services()` is NOT a plain "read every
  service" loop: regipy's own `ServicesPlugin` (recursive per-service parameter walk) took
  **~76 seconds** against a real SYSTEM hive (858 services); even a bare `iter_values()`
  per service with no recursion took **~30 seconds** — regipy parses every value's data
  unconditionally, confirmed by timing a bare `iter_subkeys()` pass (instant) against one
  that also touches values. A naive `"tor" in name.lower()` substring filter was also
  tried and rejected: `DriverStore`-shaped ImagePaths (hundreds of real services) contain
  `"tor"` as a substring of `"Store"`. The shipped design does a cheap first pass reading
  only each service's `ImagePath` (one `get_value()` call, confirmed ~7.5s for 858 real
  services) applying the same `is_tor_service_name()`/`is_tor_related()` predicates
  `is_tor_related_entry()` uses downstream, and only does the fuller `iter_values()`-style
  read for an actual match. `is_tor_related_entry()` gained two special cases (not a
  generic path check): `ARTIFACT_TYPE_PROXY_SETTINGS` dispatches to
  `constants.is_tor_proxy_config()` (`ProxyEnable==1` AND `ProxyServer` resolves to
  127.0.0.1/localhost on port 9050/9150 — handles Windows' multi-protocol
  `"socks=host:port;http=..."` shape too; disabled or wrong-port never produces a finding
  at all, per the brief), and `ARTIFACT_TYPE_SERVICE` also matches on the service's own
  name (`is_tor_service_name()`, exact `"tor"`/`"tor service"`/`"tor windows service"`) —
  independent of `ImagePath`, since an nssm-wrapped Tor service's image is `nssm.exe`, not
  `tor.exe`.
- **Phase 5 — report integration.** Three new sections, each rendered only when non-empty:
  "Network context at time of use" (Phase 3's correlation sentences/caveats plus a
  collapsed full network/interface table), "Automatic start and proxy settings" (Phase 4's
  `narrative.build_autostart_narrative()`), "Files involved" (`report._build_files_involved()`
  — a plain merge of already-tor-direct-filtered ComDlg32/RecentDocs/ShellBags findings; no
  new filtering needed since every one of those already passed `is_tor_related_entry()`).
  `narrative.describe_not_determined()` gained an opt-in `has_network_profiles` bullet
  ("which network was in use at the exact moment..."). The "portable Tor Browser never
  appears in Installed Programs" sentence (`narrative.describe_portable_install_note()`)
  was added to `report._quiet_hive_notes()` — same "silence doesn't mean absence" mechanism
  already used there for Amcache/ShimCache/BAM, gated on SOFTWARE being supplied and no
  `InstalledPrograms` finding existing. `EXECUTION_SOURCE_TYPES`/`corroborated_components`
  deliberately untouched — RunKey/Service/ProxySettings findings can still appear in a
  component's `seen_in` (real corroborating context, e.g. a RunKey entry for the same
  `firefox.exe` UserAssist already found), but never count toward the execution-source
  tally; verified end-to-end against the real evidence capture that the "Confirmed Tor
  Browser components" count (4 files, 2 corroborated) is byte-for-byte unchanged by all of
  Phase 3–5.
- Standalone CLI: `python -m modules.module_a_registry.cli` (uses `click`).
- Phase 0/1's extractors are still mostly mocked-tested only; `extract_mounted_devices()`,
  the device-correlation chain above, and Phase 3's `extract_network_profiles()`/
  `extract_network_interfaces()` **have** been verified against a real
  SYSTEM/SOFTWARE/NTUSER/UsrClass.dat capture (which also turned out to contain genuine
  Tor Browser usage — 3 launches, last run confirmed against UserAssist+BAM+MUICache) —
  `pyfwsi`/`pyfwps`'s actual ShellBags behavior remains the other piece of Phase 1 verified
  against real data (via the SystemError fix). Phase 4's RunKey/Service/ProxySettings
  extractors are mocked-tested only so far — this machine's real evidence has none of the
  three (no Tor service/autostart/proxy configured), which is a useful negative check but
  not a positive one; same "mostly mocked-only" caveat Volatility3 carries in Module C
  otherwise.

### Module B — disk (`modules/module_b_disk/`) — mostly written by teammate (branch `Sahe`)

- **Acquire** (`acquire.py`, no admin needed): copies the Tor Browser profile
  (`places/cookies/favicons.sqlite` + `-wal/-shm`, `bookmarkbackups/*.jsonlz4`) and the Tor
  daemon data dir (`state`, `cached-microdesc*`, `torrc`, `lock`, `onion-auth/*.auth_private`),
  writes a `sha256sum`-format `hashes.sha256` per copy (exactly what `evidence.verify_hashes()`
  parses) and a custody log.
  - **Auto-discovery**: with no `--tor-browser-dir`/`--disk-profile-src`/`--tor-dir-src`,
    `find_tor_browser_installations()` scans for the signature
    `Browser/TorBrowser/Data/Tor/torrc` using `core/fs_scan.py` (home/Desktop/Downloads/
    Documents first, then every drive; skip-list of system dirs; depth ≤ 8). Several installs
    → picks the one whose `torrc` was modified most recently, records the others in
    `other_installations_found`.
    Finding **no** install is a per-step error on `profile`/`tor_dir` only — the downloads
    scan (and `disk.ntfs`) still run, since a deleted install is when those matter most.
  - Plain file copy (`shutil.copy2`), **not VSS** — copying while Tor Browser runs can catch a
    sqlite db mid-write. Each file is copied independently: one that can't be read (the
    running `tor.exe` keeps `lock` locked) goes under `failed` instead of aborting the rest.
  - **Source timestamps**: every file's original created/modified/accessed times are read
    *before* copying into `filesystem_metadata.json` next to the copy (hashed by the manifest).
    Copies get fresh timestamps — on the target and again on every examiner-side `cp` — so
    this file is the only record of when tor wrote them; `analyze_tor_datadir` prefers it.
    `tor_dir`'s copy also records `tor_running_at_capture` (psutil).
  - **Live downloads scan** (`acquire_downloads.py`, Windows only): walks every drive
    (fs_scan skip-list **minus `$Recycle.Bin`**, depth ≤ 16, excluding the evidence output
    folder) for files with a `:Zone.Identifier` stream; writes
    `disk/downloads/zone_identifier_scan.json` in exactly `analyze_downloads.scan_volume()`'s
    shape (marked files hashed in place, not copied). Hits inside the Recycle Bin get
    `recycle_bin` = original path / deletion time / size from the matching `$I` file
    (`analyze_downloads.recycle_bin_info()`, shared with the mounted-volume scan; handles
    `$I` v1 and v2 and files inside deleted folders).
- **Analyze** (`__init__.py: run(config, profile_dir, tor_dir, disk_image, disk_root,
  downloads_scan)`):
  - `profile_dir` → `recover_evidence.analyze_profile()` on a verified disposable working copy
    (`evidence.working_copy()`); filters Tor Browser's shipped default bookmarks
    (`DEFAULT_BOOKMARK_URLS`). An inert profile is *expected* (permanent private browsing).
  - `tor_dir` → `analyze_tor_datadir.py`: guards used, circuits, consensus validity window,
    daemon start (`lock`), onion client-auth credentials.
  - `downloads_scan` (live scan above; auto-resolved by `analyze_evidence`, so the GUI runs it
    with no extra input) → hash-verified, then `correlate_downloads()` against
    `daemon_window()`. The window is `lock` time → newest daemon write, extended to the
    capture time when `tor_running_at_capture` (tor only rewrites `state` periodically).
    `disk_root` takes precedence when both are given.
  - `disk_image` → `carve_onion_strings.py` raw byte carve (slow, optional).
  - `disk_root` (read-only ntfs-3g mount with `show_sys_files,streams_interface=windows`) →
    `analyze_downloads.py` (Zone.Identifier internet-origin files correlated to the daemon
    window), `analyze_memory_residue.py` (pagefile/swapfile/hiberfil/crash dumps carved for
    onion addresses), `analyze_ntfs_journal.py` ($MFT + $UsnJrnl: deleted files, `.part`
    download renames → browser-family attribution, Tor file-activity timeline).
- **Report**: dedicated presenter `modules/module_b_disk/report.py`.
- Note: `acquire_all.py` never produces `--disk-image` or `--disk-root` inputs — those need a
  separate imaging step (not implemented; see §8). The downloads correlation no longer needs
  them (live scan), and `$MFT`/`$UsnJrnl`/pagefile residue now come from
  `acquire_ntfs.py`'s raw-volume export (`ntfs_dir` input; see §8).
- Sub-step isolation (commit `db2f33a`): each sub-analysis has its own try/except; a failed
  one degrades the module to `partial` with a `details["warnings"]` entry, and the dedicated
  presenter still renders. `error` is reserved for a hash-verification (`IntegrityError`)
  failure.
- `$MFT` resident content is also scanned with `AUTH_CRED_RE`: an `.auth_private` file is
  small enough to live inside its MFT record, so a deleted credential's address + key are
  recovered (`mft.resident_auth_credentials`, artifact `ntfs_onion_client_auth`; the key
  stays in `details` only, never in the artifact text or HTML).

### Module C — memory (`modules/module_c_memory/`) — the most-developed module

- **Acquire, live process** (`dumper.py`, Windows, admin): finds the **largest-RSS
  `firefox.exe`** and dumps its readable committed regions via `ctypes`
  (`OpenProcess`/`VirtualQueryEx`/`ReadProcessMemory`). Only works while Tor Browser runs.
- **Acquire, full RAM** (`winpmem_acquire.py`, Windows, admin): shells out to an
  examiner-supplied WinPMEM binary (not vendored). `--winpmem-path` is optional —
  `find_winpmem_binaries()` scans (same `core/fs_scan.py` walker) for any `*winpmem*.exe`.
  In `acquire_all.py` the full-image capture is **always attempted, independent of the live
  dump** (the live dump can only ever capture a running process; WinPMEM covers exited ones).
- **Analyze** (`analyzer.py`): chunked ASCII + UTF-16LE string extraction, then regex
  families: URLs (host-anchored to `--onion`/`--host`), cookies, `?q=` search queries,
  credentials (`field=value` and JSON), downloads (`file://` + Windows paths), onion domains
  (→ `targeting_suggestions`). Binary `confidence: high|low` via `_is_noise_value()` etc.
  On `source_type="full-memory"` with targets set, credentials/search queries must co-occur
  with the target host in the same extracted string ("host anchoring"); failures go to
  `host_anchoring.unanchored`. Produces `key_findings` (deduped, high-confidence only) and an
  offset-ordered pseudo-timeline (explicitly **not** chronological).
- **Structural pass** (`volatility_analyze.py`, opt-in `--vol3-path`): shells out to
  Volatility3's `vol` CLI (psscan/netscan/filescan/cmdline/hivelist) — never imported
  in-process. `--vol3-extract-process firefox.exe` narrows a full image to one process first.
- **Report** (`report.py`): site map, near-duplicate path detection, JWT-ish cookie decoding,
  download ↔ site-map matching, clustered/far-offset timeline flags, vol3 corroboration notes.
- Target test app used in the VM experiments: a team-built hidden service (context.md mentions
  `127.0.0.1:5000` and cookies `session` / `trance_user` / `trance_pref`).

---

## 5. How to run everything

### Target machine (Windows, elevated)
```powershell
# From source:
python acquire_all.py --output-dir evidence
# Or the built exe (build it from a NON-admin shell, run it as admin):
python -m PyInstaller --onefile --name trance-acquire acquire_all.py
dist\trance-acquire.exe --output-dir evidence
```
Flags: `--skip-registry/--skip-memory/--skip-disk`, `--ntuser-user`, `--winpmem-path`,
`--tor-browser-dir`, `--disk-profile-src`, `--tor-dir-src`, `--skip-ntfs`, `--ntfs-volume`,
`--skip-pagefile`, `--include-hiberfil`. Omitting the path flags triggers
auto-discovery. Every category prints its outcome now (it didn't before commit `95b462c` —
memory/disk used to fail silently).

Output:
```
evidence/
  registry/  SYSTEM_<ts>, SOFTWARE_<ts>, NTUSER_<ts>.DAT, UsrClass_<user>_<ts>.dat,
             Amcache_<ts>.hve (+ .sha256, custody json)
  memory/    firefox_<pid>_<ts>.bin and/or fullmem_<ts>.raw (+ .sha256, custody json)
  disk/      profile/, tor_dir/ (each with hashes.sha256) + custody json
             ntfs/<letter>/ MFT, UsnJrnl_J, pagefile.sys, swapfile.sys, ntfs_metadata.json
  acquire_manifest.json   status + path per artifact
```

### Examiner machine
```bash
source .venv/bin/activate
# Explicit flags:
python main.py --case demo --output-dir output \
    --ntuser ... --system ... --amcache ... --software ... --usrclass ... \
    --disk-profile ... --tor-dir ... [--disk-root ...] [--disk-image ...] \
    --dump ... --source-type full-memory --onion X.onion --host 1.2.3.4:5000 --username alice \
    [--vol3-path vol --vol3-extract-process firefox.exe]
# Point at an acquire folder instead (reads acquire_manifest.json, or globs if absent):
python analyze_evidence.py --case demo --evidence-dir evidence --onion X.onion --host ...
# Desktop app:
pip install -r requirements-gui.txt && python gui_main.py [--output-dir output]
```
`analyze_evidence.resolve_evidence()` accepts both the `acquire_all.py` layout
(`registry/`, `memory/`, `disk/profile`, `disk/tor_dir`) and a **flat** folder (the older
individual-script VM captures in `../vm-shared/` are flat). It excludes `.sha256` sidecars
from the extension-less `SYSTEM_*` glob, and prefers a full-memory image over a live dump.

### Dev loop
```bash
source .venv/bin/activate
python -m pytest -q          # ~210 tests, ~5s
ruff check . && black --check .
```

---

## 6. Desktop GUI (`gui/`, PySide6 + QtWebEngine)

- `main_window.py` — `QTabWidget`: **Analyse**, **Report**, **History**. Wires signals:
  analysis finished → load report + refresh history; history "view" → load report;
  history delete → clear report tab if it showed that case + refresh recent cases.
- **The GUI is the primary analysis interface** and covers every analysis-side CLI flag;
  `main.py`/`analyze_evidence.py` stay as the engine and a scriptable fallback.
  `trance-acquire.exe` stays CLI (it runs on the target).
- `analyse_tab.py` — 720px centered, scrollable form: evidence folder (optional; read-only,
  `NoFocus`, drag-and-drop), case name, and collapsible sections (`advanced_inputs.py`):
  targeting; **Review detected inputs** (each auto-discovered input with Change…/reset —
  the `--system/--ntuser/--amcache/--dump/--disk-profile/--tor-dir/--downloads-scan`
  overrides); **disk image or mounted volume** (`--disk-image` carve, mount-from-the-app,
  or an already-mounted `--disk-root`); **memory options** (`--source-type`, `--vol3-path`
  auto-filled from PATH, `--vol3-extract-process/-pid`). Run becomes **Cancel** while
  running. Bottom panel: **Recent cases** idle, **Live log** while running.
- `analysis_request.py` (Qt-free) — `AnalysisRequest` dataclass = the form; `effective_inputs()`
  merges `resolve_evidence()` with overrides; `validate()` mirrors `main.main()`'s rules plus
  form-only ones (returns errors + warnings). JSON round-trip for the child process.
- `analysis_runner.py` (Qt-free) — the analysis runs as a **child process** (`gui_main.py
  --run-analysis <request.json>`; frozen: the same exe re-launches itself) so Cancel can stop
  it; stdout carries log lines plus `@@TRANCE {json}` progress/result/error lines. Cancel
  removes the case folder only if this run created it.
- `mount_helper.py` (stdlib only, **runs as root via pkexec**, `gui_main.py --mount-helper` when
  frozen) — validates the image (regular file; refuses VirtualBox *differencing* VDIs by
  header type 4 at 0x4C), `qemu-nbd --read-only`, mounts the largest NTFS partition with
  ntfs-3g `ro,show_sys_files,streams_interface=windows` under `/run/trance-mounts/`, then
  waits: "unmount" on stdin **or stdin EOF** (GUI gone) unmounts and detaches. One password
  prompt per run. Linux only (`processes.mount_support()` disables it elsewhere).
  **Verified for real** by the user (2026-10-04, Linux/GNOME/Wayland, flattened VM `.vdi`).
  Formats: raw, `.vdi`, `.vmdk`, `.vhd(x)`, `.qcow2` — **not E01** (would need `ewfmount`).
- `processes.py` — Qt wrappers: `AnalysisProcess` (QProcess, signals, terminate→kill cancel)
  and `MountSession`. Analyse tab order: mount → analyse with `disk_root=<mountpoint>` →
  unmount → show result; also unmounts on failure/cancel/window close.
- Progress bar: 0–100 with a `QTimer` easing toward the last real checkpoint (25/50/75/100).
  Honest limitation: there are only 4 real checkpoints; it's visual smoothing.
- `report_tab.py` — `QWebEngineView` loading the existing `report.html` (paths must be
  resolved to absolute before `QUrl.fromLocalFile`).
- `history_tab.py` — scans `<output-dir>/*/findings.json` (no separate DB, by design).
  Sortable table with filter box, relative-time "Generated" column (ISO in tooltip), status
  chips painted by a `QStyledItemDelegate`, selection-gated View/Delete, Delete behind a
  confirmation dialog (`shutil.rmtree` of the case dir).
- `history.py`, `pipeline_inputs.py`, `analysis_request.py`, `analysis_runner.py`,
  `mount_helper.py` — **Qt-free** pure logic, unit-tested without PySide6.
  Keep new logic Qt-free where possible; CI does not install PySide6.
- `theme.qss` + `theme.py` — styling matching the report's CSS tokens (`--bg #14181b`,
  `--surface #1b2126`, `--accent #e2694f`, `--confirm #4fae84`, `--noise #c9a552`, …).

Qt gotchas already hit (don't rediscover them):
- QSS has no `letter-spacing`, `text-transform`, or `transform` — done via `QFont`/`QPainter`
  in `theme.py`.
- `QTableWidgetItem` aliases `DisplayRole` and `EditRole` to one slot — use a subclass with
  `__lt__` (`_GeneratedItem`) for display-vs-sort-key splits.
- `setCellWidget()` widgets don't move with `sortItems()` — use a delegate.
- Row → data lookups must go through `item.data(UserRole)`, not a parallel Python list
  (breaks after sorting).
- A read-only `QLineEdit` still takes focus by default (showed a permanent accent border).
- The GUI has been verified **offscreen** (`QT_QPA_PLATFORM=offscreen`, incl. full and
  cancelled runs) and by the user on Linux/Wayland (incl. the in-app mount); never on
  Windows. On Wayland without GBM, QtWebEngine segfaulted on page load until `gui_main.py`
  defaulted `QTWEBENGINE_CHROMIUM_FLAGS=--disable-gpu`.

---

## 7. Packaging status

**Nothing is fully packaged or released yet.** Current state:

| Exe | Source | Status |
|---|---|---|
| `trance-acquire` | `acquire_all.py` | Built ad hoc once on the Windows VM (`C:\forensics\TRANCE-new`); ran successfully 2026-09-29 (registry ✓, disk ✓ via auto-discovery, memory ✗ because Tor Browser wasn't running and WinPMEM auto-discovery didn't exist yet). **Not rebuilt/retested since commit `a544840`.** |
| `trance-analyze` | `analyze_evidence.py` | Linux build only (dev proxy + a local `dist/` build). Never built/run on Windows. |
| `trance-gui` | `gui_main.py` | Linux build only (~290 MB `--onefile`, QtWebEngine). Never built/run on Windows. |

Build commands (from repo root; on Windows use `;` instead of `:` in `--add-data`):
```bash
pyinstaller --onefile --name trance-acquire acquire_all.py
pyinstaller --onefile --name trance-analyze analyze_evidence.py \
  --hidden-import modules.module_a_registry --hidden-import modules.module_b_disk \
  --hidden-import modules.module_c_memory \
  --collect-all tzdata \
  --add-data "report_template.html.j2:." \
  --add-data "modules/module_c_memory/report_template.html.j2:modules/module_c_memory"
# trance-gui: same flags as trance-analyze plus --collect-all PySide6, entry gui_main.py
```
`--collect-all tzdata` is required on both trance-analyze and trance-gui: Windows has no
OS-level tz database, so `zoneinfo` (report-timezone display, both CLI and GUI) depends
entirely on the `tzdata` package's data files, which PyInstaller's default import analysis
does not follow (they're not `.py` modules). Without it every zone name silently fails to
resolve in the built exe even though it works fine from source.
PyInstaller never cross-compiles: Windows exes must be built on Windows. `*.spec`, `build/`,
`dist/` are gitignored.

---

## 8. TODO — what still needs doing (prioritized)

### P0 — bugs that will bite on the next real run

1. ~~Manifest paths not rebased onto `--evidence-dir`~~ — **fixed**. `acquire_all.py` now
   writes evidence paths relative to the output dir with `/` separators
   (`_make_paths_portable`; source locations like `winpmem_path` are left as recorded), and
   `analyze_evidence._rebase_onto()` maps any recorded path — old-style
   `evidence\\registry\\...`, absolute `C:\\...`, or new-style `registry/...` — onto the
   current evidence folder by its longest existing trailing component run. Verified against
   the real VM manifest in `../vm-shared/`. A manifest entry whose file wasn't copied still
   resolves to a (missing) path inside the evidence folder on purpose — it never silently
   substitutes a different acquisition's file.
2. Rebuild `trance-acquire.exe` from current `dev` and do a real run **with Tor Browser open
   and a WinPMEM binary present**, to verify the live dump and the full-image path for real.
   The acquire folder must be copied **whole** — the 2026-09-29 copy in `../vm-shared/` is
   missing its `registry/` subfolder (the `SYSTEM_20260918…` hives at its root are an older,
   separate run).

### P1 — rule-based findings instead of regex-hit dumping (the main quality problem)

The report's stated goal is "every interpretive note is a fixed, auditable rule". In
practice Module C turns every regex hit into a finding. Measured on
`output/Test002/findings.json` (full-memory image): **4,017 Module C artifacts** —
3,106 `download` (1,962 of them the analyzer's *own* `confidence: low`), 685
`search_query`, 213 `credential` (106 low), 13 `cookie` (12 low). Concretely:

- `analyzer.record_artifact()` is called for **every** hit regardless of confidence, so
  low-confidence noise lands in `findings.json["artifacts"]` and the generic tables.
- Examples of noise recorded as evidence: `file:///%s` (printf format strings), the Tor
  Browser install's own `firefox.exe` path, search "queries" like `%s` and `google`, and
  **the examiner's own activity on the target** (`winpmem+download+for+Windows`) — the
  acquisition process contaminates the evidence and nothing filters it.
- `COOKIE_RE` is hardcoded to the test app's cookie names
  (`session|trance_user|trance_pref`) — won't generalize to any real target.
- `CREDENTIAL_FIELDS` includes very generic names (`user`, `login`, `email`); 68 "high
  confidence" credentials in one run is not believable.
- Confidence is a binary label from ad-hoc heuristics (`_is_noise_value`, path shape) with
  no record of *why*.

Suggested design (discuss with the user before building — they asked for a plan-first
workflow on large changes):
- Split **observations** (all raw hits — keep in `details` for transparency, as today) from
  **findings** (emitted only when a named rule fires). `findings.json["artifacts"]` should
  contain findings only.
- A small rule registry (e.g. `core/rules.py` or `rules/`): each rule has `id`, `module`,
  `artifact_type`, a predicate over the observation + case context, a tier
  (e.g. `confirmed / corroborated / indicator / context`), and a human-readable rationale
  that the report prints next to the finding. Deterministic, unit-testable per rule.
- Built-in exclusion rules: Tor Browser shipped defaults (reuse
  `recover_evidence.DEFAULT_BOOKMARK_URLS`, default onion services), format strings,
  TRANCE/acquisition tool artifacts (`trance-acquire`, `winpmem`, `python`, `pyinstaller`,
  the evidence output path), and anything inside the acquisition time window
  (`acquire_manifest.json["acquired_at"]`).
- **Cross-module corroboration** is claimed by the README but not implemented (only Module A
  correlates across its own hives). Candidate rules: an onion address seen in memory *and*
  in NTFS/USN or an `onion-auth` credential; Tor execution in UserAssist/Amcache *and* the
  daemon's `lock`/`state` window; a download seen in memory *and* as a Zone.Identifier file
  *and* as a USN `.part` rename. This probably belongs in a new post-module step between
  `run_pipeline`'s module loop and `build_findings`.
- Parameterize target-specific patterns (cookie names etc.) via CLI/GUI inputs instead of
  constants.
- Evaluate with ground truth: the team ran scripted VM scenarios (`output/vm-run-*`); build
  golden-file tests that assert expected findings present and known-noise absent, and track
  precision/recall.

### P1 — packaging

- Commit curated `.spec` files or a build script (Makefile targets / `scripts/build.py`) so
  the hidden-imports/add-data/collect-all flags aren't retyped by hand.
- A `windows-latest` GitHub Actions job that builds the three exes and uploads artifacts.
- Version stamping, code signing / AV-allowlisting guidance (onefile exes get flagged).
- Decide WinPMEM distribution: currently examiner-supplied and auto-discovered; check its
  license before bundling.
- Build from a non-admin shell (PyInstaller warns and v7 will refuse elevated builds).
- Python version drift: `pyproject` says ≥3.10, CI uses 3.12, the VM has 3.14.

### P2 — forensic soundness

- `acquire_all.py` defaults `--output-dir evidence` relative to the CWD — i.e. writes onto
  the target's own disk, overwriting unallocated space. Default to / strongly recommend
  external media, warn when the output dir is on the system volume, and check free space
  before a multi-GB WinPMEM image.
- Installing Python/git/pip on the target (as done on the VM) is itself contamination — the
  exe exists to avoid that. Document building on a separate Windows machine and carrying
  the exe on removable media.
- Disk acquisition copies live sqlite without VSS; reuse Module A's `_copy_via_shadow`.
- `dumper.py` only dumps the single largest-RSS `firefox.exe`; Tor Browser is
  multi-process and content processes hold page data. Consider dumping all of them.
- Only one Tor Browser install is acquired and the analyze side only accepts one
  profile/tor_dir pair end to end (acquire → manifest → `module_b_disk.run`).
- No acquire step produces a disk image or the read-only mount `--disk-root` needs (the
  `$MFT`/`$UsnJrnl`/pagefile part of that is now covered by `acquire_ntfs.py`, below).
- **NTFS metadata collection in trance-acquire — built 2026-10-07, not yet run on Windows.**
  `modules/module_b_disk/acquire_ntfs.py` (stdlib, Windows, admin) reads raw volumes and
  writes `disk/ntfs/<letter>/{MFT, UsnJrnl_J, pagefile.sys, swapfile.sys}` +
  `ntfs_metadata.json` + `hashes.sha256`; manifest `disk.ntfs`. `$MFT`/`$J` come from a VSS
  snapshot device (Module A's WMI create / vssadmin delete), falling back to the live volume
  (`metafile_source` records which); pagefile/swapfile always from the live volume (VSS
  excludes them), with a free-space check; hiberfil opt-in. `$J` is copied as allocated runs
  only (extents with original stream offsets in the metadata). The exported `MFT` is the
  **on-disk bytes** (fixups not applied) — what `analyze_ntfs_journal` expects; `ntfscat`
  output differs only at the fixup bytes. Volumes = system drive + every drive a Tor install
  was seen on (`acquire_all.ntfs_volumes()`), and the step runs even when the disk step found
  no install (the deleted-install case). Flags: `--skip-ntfs`, `--ntfs-volume X`
  (repeatable), `--skip-pagefile`, `--include-hiberfil`. Analyze side: `--ntfs-dir` / GUI
  "NTFS metadata" input → Module B hash-verifies each volume, runs `analyze_ntfs` +
  `carve_residue` per volume and merges them (`merge_ntfs_reports`/`merge_residue_reports`,
  paths prefixed `C:\`); `disk_root` wins when both exist.
  Verified: unit tests on a hand-built volume (fragmented `$MFT` via attribute list, sparse
  `$J`, negative LCN deltas, uninitialized tail, deleted same-name record); a real
  `mkntfs`/`ntfscp` volume (pagefile byte-identical; `$MFT` equal to `ntfscat` after
  fixups); the Windows-formatted `~/tor-transfer/evidence.vdi` data disk (same `$MFT`
  equality; that disk has no `$UsnJrnl`). **Still to do:** rebuild `trance-acquire.exe` and
  run it on the VM — the raw `\\.\C:` / shadow-device reads, a real `$J`, a 1 GB+ `$MFT`
  and multi-GB pagefile are untested; then compare against a `--disk-root` run of the same
  machine's image.

### P2 — smaller cleanups

- `README.md` stale bits: says Module A returns `not_implemented`, and says WinPMEM/full-RAM
  capture is "future work". `context.md` says Modules A/B are stubs.
- CI's `compileall` step skips `gui/`, `acquire_all.py`, `analyze_evidence.py`, `gui_main.py`.
- `yara-python` is in requirements but unused; `volatility3` is only needed as the external
  `vol` CLI; `click` is only used by `modules/module_a_registry/cli.py`.
- GUI: Recent Cases shows raw ISO timestamps (History uses relative time); case-name and
  output checks exist in both `main.py` and `gui/analysis_request.validate()`. The in-app
  mount needs pkexec + a polkit agent; it has only been run on GNOME (other desktops need
  their own polkit agent running). E01 images can't be mounted from the app yet.
- `output/` contains stale results from older code (e.g. `output/vm-run-*` predate Module A;
  `output/Test002` shows `host_anchoring.applied: false` although current code applies it for
  that input — verified with a synthetic dump). Don't treat old outputs as current behavior.

---

## 9. Environment and workflow notes

- Dev machine: Linux, repo at `~/Documents/Projects/cysec-project/Trance`, venv `.venv`
  (has PySide6 + PyInstaller installed). Evidence captured on the VM is shared via
  VirtualBox folder `\\VBOXSVR\vm-shared` ↔ `~/Documents/Projects/cysec-project/vm-shared`.
- Target: Windows 10 VirtualBox VM (user `vboxuser`), Python 3.14. Use the checkout at
  `C:\forensics\TRANCE-new` (branch `dev`). The older `C:\forensics\TRANCE` has unrelated git
  history (upstream history was rewritten once — see branch `main-backup-before-trailer-strip`)
  and should not be pulled into. `pyinstaller` isn't on PATH there: use
  `python -m PyInstaller`.
- Git: remote `https://github.com/Neela30/Trance`; work happens on `dev`, PRs go `dev → main`.
  Teammate branches: `Neela`, `Sahe` (Module B), `Thila`. Teammates push to `dev` too — pull
  before large changes.
- The user commits via explicit "commit" instructions; don't commit unprompted. They usually
  want a plan before large features and direct implementation for well-specified fixes.
- Tests that touch auto-discovery **must mock** `find_tor_browser_installations` /
  `find_winpmem_binaries` (or `core.fs_scan` roots). Unmocked, they scan the real home
  directory — this slipped in twice already (3–20s tests). Use `pytest --durations=10` after
  adding tests to catch it.
- Windows-only code paths are tested with `monkeypatch` on `sys.platform`, `is_admin`, and
  `subprocess.run`; they have not been exercised for real beyond the one VM run above.
