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
  `ok | skipped | not_implemented | error`.
- `artifacts`: flat list of `core.schema.Artifact(module, artifact_type, source, description,
  sha256, timestamp)` — goes into `findings.json["artifacts"]` for every module.
- `details`: arbitrary module-specific dict kept verbatim under
  `findings.json["modules"][name]["details"]` — this is what the report presenters read.
- Heavy analysis imports are done **lazily inside `run()`** so the acquire scripts living in
  the same package stay importable without regipy etc. Keep it that way.
- A module that raises is caught by `main.run_module()` and recorded as `error`; it never
  stops the other modules.

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

- **Acquire** (`acquire.py`, Windows, admin): `reg save HKLM\SYSTEM` and `reg save HKCU`
  (current user's NTUSER.DAT); Amcache.hve via a Volume Shadow Copy created with WMI
  (`Win32_ShadowCopy.Create()` through PowerShell — `vssadmin create shadow` is Server-only,
  confirmed on real client Windows) and deleted with `vssadmin delete shadows` afterwards.
  `--ntuser-user <name>` pulls another user's NTUSER.DAT via VSS. Each hive independent.
- **Analyze** (`pipeline.py`): hash on ingest → regipy extraction (`extractors.py`:
  UserAssist, RecentDocs from NTUSER; ShimCache from SYSTEM; Amcache) → Tor-relevance filter
  (`constants.py: is_tor_related`) → normalize to `Artifact`s (`normalize.py`) → re-hash and
  raise `IntegrityError` on mismatch.
- **Filter philosophy**: deliberately *recall over precision* — substring path markers
  (`"tor browser"`, `"torbrowser"`, `"\\tbb\\"`, `"torproject"`, …) plus a list of
  Tor-specific executable names. `firefox.exe` alone is intentionally NOT a match.
- **Report** (`report.py`): dedupes, builds a per-component timeline across hives, and counts
  components *corroborated by 2+ independent hive sources* — the only real correlation logic
  in the codebase right now, and only within Module A.
- Standalone CLI: `python -m modules.module_a_registry.cli` (uses `click`).
- Real runs produce ~21 artifacts — manageable, low noise.

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
  - Plain file copy (`shutil.copy2`), **not VSS** — copying while Tor Browser runs can catch a
    sqlite db mid-write. Each file is copied independently: one that can't be read (the
    running `tor.exe` keeps `lock` locked) goes under `failed` instead of aborting the rest.
  - **Source timestamps**: every file's original created/modified/accessed times are read
    *before* copying into `filesystem_metadata.json` next to the copy (hashed by the manifest).
    Copies get fresh timestamps — on the target and again on every examiner-side `cp` — so
    this file is the only record of when tor wrote them; `analyze_tor_datadir` prefers it.
    `tor_dir`'s copy also records `tor_running_at_capture` (psutil).
  - **Live downloads scan** (`acquire_downloads.py`, Windows only): walks every drive
    (fs_scan skip-list, depth ≤ 16, excluding the evidence output folder) for files with a
    `:Zone.Identifier` stream; writes `disk/downloads/zone_identifier_scan.json` in exactly
    `analyze_downloads.scan_volume()`'s shape (marked files hashed in place, not copied).
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
  them (live scan), but `$MFT`/`$UsnJrnl` and pagefile/hiberfil residue still do.
- Known gap: any sub-step error (e.g. an incomplete profile) sets the whole module to
  `error`, and the report then drops Module B's dedicated presenter for the generic table.

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
`--tor-browser-dir`, `--disk-profile-src`, `--tor-dir-src`. Omitting the path flags triggers
auto-discovery. Every category prints its outcome now (it didn't before commit `95b462c` —
memory/disk used to fail silently).

Output:
```
evidence/
  registry/  SYSTEM_<ts>, NTUSER_<ts>.DAT, Amcache_<ts>.hve (+ .sha256, custody json)
  memory/    firefox_<pid>_<ts>.bin and/or fullmem_<ts>.raw (+ .sha256, custody json)
  disk/      profile/, tor_dir/ (each with hashes.sha256) + custody json
  acquire_manifest.json   status + path per artifact
```

### Examiner machine
```bash
source .venv/bin/activate
# Explicit flags:
python main.py --case demo --output-dir output --ntuser ... --system ... --amcache ... \
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
- The GUI has only been verified **offscreen** (`QT_QPA_PLATFORM=offscreen`) and visually by
  the user on Linux; never on Windows.

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
  --add-data "report_template.html.j2:." \
  --add-data "modules/module_c_memory/report_template.html.j2:modules/module_c_memory"
# trance-gui: same flags as trance-analyze plus --collect-all PySide6, entry gui_main.py
```
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
- No acquire step produces a disk image or the read-only mount `--disk-root` needs.

### P2 — smaller cleanups

- `README.md` stale bits: says Module A returns `not_implemented`, and says WinPMEM/full-RAM
  capture is "future work". `context.md` says Modules A/B are stubs.
- CI's `compileall` step skips `gui/`, `acquire_all.py`, `analyze_evidence.py`, `gui_main.py`.
- `yara-python` is in requirements but unused; `volatility3` is only needed as the external
  `vol` CLI; `click` is only used by `modules/module_a_registry/cli.py`.
- GUI: Recent Cases shows raw ISO timestamps (History uses relative time); case-name and
  output checks exist in both `main.py` and `gui/analysis_request.validate()`. The in-app
  mount needs pkexec + a polkit agent; its root path (qemu-nbd/ntfs-3g) is covered
  only by unit tests of the pure parts until a real run through the GUI.
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
