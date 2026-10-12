# TRANCE
### A Forensic Artifact Triage Tool for Tor Browser Activity

TRANCE is an automated digital-forensics tool that reconstructs Tor Browser 
usage on Windows 10/11 systems by acquiring, parsing, and correlating evidence 
across registry, disk, and memory artifacts — the three layers most likely to 
survive Tor Browser's privacy-preserving design.

Existing general-purpose forensic suites (EnCase, FTK, AXIOM) provide broad 
file-system and registry browsing but encode no Tor-specific knowledge, leaving 
examiners to manually correlate scattered artifacts by hand. TRANCE closes that 
gap with three automated modules — registry & execution evidence, disk & 
database artifacts, and memory analysis — unified by a shared SHA-256 hashing 
and chain-of-custody layer, and merged into a single reproducible HTML/JSON 
report.

Built as a CS3400 Cyber Security coursework project, evaluated against 
synthetic ground-truth data across live, shutdown, and hibernation capture 
scenarios.

**Status:** In development · **Platform:** Windows 10/11 (target) · 

## Running the pipeline

`main.py` runs every module, merges their output into one `findings.json`, and
renders the HTML case report from it:

```
python main.py --case demo --output-dir output \
    --dump captures/firefox_<pid>_<ts>.bin \
    --onion <address>.onion --host 127.0.0.1:5000 --username alice
```

Writes to `output/demo/`:

- `findings.json` — every module's status plus a flattened, cross-module
  `artifacts` list (each entry carries its `module`), and each module's
  richer structured output under `modules.<name>.details`.
- `report.html` — the case report, rendered deterministically from
  `findings.json` (`report.py` + `report_template.html.j2`, Jinja2). No
  external services, no network, no LLM: every interpretive note in the
  report is a fixed, auditable rule.
- `custody.json` — chain-of-custody entries for the evidence analyzed and
  the outputs generated (`core.custody_log`).

Modules are isolated: one that is not implemented yet, given no evidence
this run, or that raises is recorded with that status and does not stop
the others. Exit code is `2` if any module errored, else `0`.

The three modules run at the same time and their results are assembled in a
fixed order, so `findings.json` doesn't depend on which finished first. Each
module's wall-clock time is recorded in `findings.json` under
`modules.<name>.duration_seconds`. Set `TRANCE_WORKERS=1` to run everything
sequentially (it also turns off the memory scan's worker processes);
`TRANCE_WORKERS=<n>` caps those workers (default: up to 8). On a full
8.6 GB RAM capture the whole pipeline takes about two and a half minutes.

### Module contract

Each `modules/<name>/__init__.py` exposes

```python
def run(config: core.config.TranceConfig, **kwargs) -> core.schema.ModuleResult
```

returning `ModuleResult(module, status, artifacts, details, message)` where
`status` is one of `ok` / `partial` / `skipped` / `not_implemented` / `error`
(`partial`: some sub-steps failed but real findings were produced, see
`details["warnings"]`),
`artifacts` is a list of `core.schema.Artifact`, and `details` is any
module-specific dict worth keeping verbatim in `findings.json`. Module-specific
CLI flags are declared in `main.py` and passed through as `kwargs`. To
contribute a custom section to the HTML report, register a presenter in
`report.py`'s `PRESENTERS`; without one a module gets a generic artifact table.

Module A (registry) runs when at least one registry hive is supplied, Module B
when at least one disk evidence path is supplied, and Module C when a memory
image is supplied; each otherwise returns `skipped`.

### Run disk analysis through the pipeline

Pass each extracted evidence source explicitly. The profile and Tor daemon
directory are analyzed from verified disposable copies. Raw carving is optional
because a full image can take a long time to scan:

```sh
python main.py --case disk-run-1 --output-dir output \
    --disk-profile /path/to/acquired/profile \
    --tor-dir "/path/to/Tor Browser/Browser/TorBrowser/Data/Tor"

# Add this only when a full raw-byte scan is intended:
#   --disk-image /path/to/disk.vdi

# Add this to analyze the whole mounted volume. Mount it read-only through
# ntfs-3g with the metafiles and named streams exposed:
#   sudo mount -t ntfs-3g -o ro,show_sys_files,streams_interface=windows /dev/nbd0p2 /mnt/evidence-volume
#   --disk-root /mnt/evidence-volume
# It then runs three passes:
#   1. Internet-origin files: every file carrying a Zone.Identifier stream,
#      anywhere on the volume, with its NTFS creation time, flagged inside/
#      outside the Tor daemon's last active window when --tor-dir is given.
#      Tor Browser strips the source URL from that stream by design.
#   2. Memory residue: pagefile.sys, swapfile.sys, hiberfil.sys and crash dumps
#      carved for onion addresses -- the only disk route to a visited public
#      onion service, and only if Windows paged or hibernated during the session.
#   3. NTFS metadata: $MFT (deleted files' names, resident content and
#      Zone.Identifier streams) and the $UsnJrnl change journal (client-auth
#      credential filenames, a Tor file-activity timeline, and downloads
#      reconstructed from the browser's temp-file rename -- Firefox/Tor Browser's
#      "<8 chars>.<ext>.part" naming attributes the download to that browser
#      family even after the file is deleted). Without show_sys_files this pass
#      reports itself unavailable instead of failing the module.
```

All supplied Module B results are stored under
`modules.module_b_disk.details` in `findings.json`; selected findings are also
flattened into its `artifacts` array and shown in the HTML report. `--evidence-dir`
remains case-level provenance metadata and does not select a Module B parser.

## Module C — Memory forensics

Split into two tools because live process memory only exists while the
process is alive, but analysis should be re-runnable offline against a saved
capture: **acquire once, analyze forever.**

- `modules/module_c_memory/dumper.py` — runs on Windows, while Tor Browser is
  open. Finds every `firefox.exe` process, picks the one with the largest
  RSS (the main process holding browsing data), and dumps its readable
  committed memory regions to a `.bin` file via `ctypes`
  (`OpenProcess` + `VirtualQueryEx` + `ReadProcessMemory` — no `procdump`,
  no `pywin32`). Writes a `.sha256` sidecar and a custody-log entry
  (`core.hashing`, `core.custody_log`) alongside the dump.
- `modules/module_c_memory/analyzer.py` — runs anywhere, offline, against a
  saved `.bin`. Extracts printable strings (ASCII + UTF-16LE, chunked so it
  handles multi-GB dumps) and reports them **anchored to a known target**
  so output is signal, not the process's entire address space of Firefox
  code, symbols, and its built-in default onion list.

### Acquire (Windows, as Administrator, Tor Browser running)

```
python -m modules.module_c_memory.dumper --output-dir captures
```

Admin rights are required for `OpenProcess` to succeed against another
user's process; failure is detected and reported clearly rather than
failing silently. Prints the selected PID, region count, total size, and
SHA-256 of the dump.

### Analyze (any machine, offline)

```
python -m modules.module_c_memory.analyzer captures/firefox_<pid>_<ts>.bin \
    --onion <address>.onion \
    --host 127.0.0.1:5000 \
    --username alice \
    --cookie-name sid --cookie-name csrf_token
```

- `--onion` / `--host` anchor URL matching to the target hidden service —
  without at least one of these the targeted-URL section is empty.
- `--username` highlights recovered search queries (`?q=<value>`) that
  match a known test user, and anchors recovered login credentials and form
  bodies to that account.
- `--cookie-name` (repeatable) names the cookies to look for. Default:
  `session`, `trance_user`, `trance_pref` (the control test site's) -- give the
  target's own names for a real case.
- `--workers N` sets the worker processes for the scan (default up to 8, or
  `TRANCE_WORKERS`; `1` = sequential). The image is split into segments scanned
  in parallel and hashed once alongside; results are identical to a sequential
  scan.
- Reports, anchored to the target: target URLs; cookies **by name** (see
  `--cookie-name` above); search queries; login credentials; posted form
  bodies (e.g. a contact-form message); and the titles of the target site's
  pages. Anchoring differs by kind, because each sits differently in memory:
  - **Credentials** are found as a field name followed a few bytes later by its
    typed value (Firefox stores them as separate strings), and kept when the
    `--username` is one of the values or a target mention is within 2 KiB.
    `field=value` and JSON shapes are still matched; neither matches bare code
    identifiers such as `Pass::draw_indexed` or `LoginManager.sys.mjs`.
  - **Form bodies** (`name=value&name=value`) use the same anchor.
  - **Page titles** can't be anchored by distance, so a `<title>` is kept when
    the page's own HTML links to at least three paths this analysis already saw
    under the target host.
  - **Cookies** sit far from any host string and are found by name only.
  The anchoring needs `--onion`, `--host` or `--username`; without one, the new
  credential/form/title extractors emit nothing.
- Only findings become `artifacts` in `findings.json`: one per distinct
  high-confidence cookie/credential/download, search query and target URL.
  Every raw observation (low-confidence ones included, with all offsets) stays in
  `details.targeted`, so nothing is hidden, just not presented as a finding.
- A separate **unfiltered** section reports counts and a capped sample of
  all URL-like and session/token/auth-like strings, clearly labelled as
  noisy context — not evidence on its own.
- If a `.sha256` sidecar sits next to the `.bin`, integrity is verified
  before analysis and a mismatch aborts with an error.
- Emits both a JSON report (`<dump>.report.json`) and a readable summary
  on stdout. This standalone run is for quick re-targeting of one dump; the
  HTML case report comes from `main.py` (see *Running the pipeline*).

### Building the dumper as a standalone `.exe`

Build on Windows (PyInstaller does not cross-compile):

```
pip install pyinstaller psutil
pyinstaller --onefile --name trance-memdump modules/module_c_memory/dumper.py
```

The resulting `dist/trance-memdump.exe` needs no Python install on the
target machine. Note: `--onefile` binaries are commonly flagged by AV as
suspicious (self-extracting, unsigned) — expect to allowlist it or sign it
for use in a live environment.

## Packaging for deployment: one acquire exe, one analyze exe

`dumper.py`/`winpmem_acquire.py`/`module_a_registry/acquire.py` above can
each be packaged standalone, but for a full case `acquire_all.py` and
`analyze_evidence.py` wrap all three modules' acquisition steps into a
single exe per side, sharing one evidence folder:

```
evidence/
  registry/   SYSTEM_*, NTUSER_*.DAT, Amcache_*.hve
  memory/     firefox_<pid>_*.bin and/or fullmem_*.raw
  disk/
    profile/  places.sqlite, cookies.sqlite, favicons.sqlite, bookmarkbackups/
    tor_dir/  state, cached-microdesc-consensus, ...
  acquire_manifest.json
```

**On the target (Windows, as Administrator):**

```
pyinstaller --onefile --name trance-acquire acquire_all.py
trance-acquire.exe --output-dir evidence --tor-browser-dir "C:\path\to\Tor Browser"
```

Close Tor Browser first if possible — the disk copy is a plain file copy,
not a Volume Shadow Copy like Amcache.hve, so a still-running browser can
leave a sqlite db mid-write. Registry and memory acquisition need
elevation; each of the three categories (registry/memory/disk) is
independent, so one failing doesn't block the others or the manifest.

Copy the whole `evidence/` folder to the examiner's machine.

**On the examiner's machine:**

```
pyinstaller --onefile --name trance-analyze analyze_evidence.py \
    --hidden-import modules.module_a_registry \
    --hidden-import modules.module_b_disk \
    --hidden-import modules.module_c_memory \
    --collect-all tzdata \
    --add-data "report_template.html.j2:." \
    --add-data "modules/module_c_memory/report_template.html.j2:modules/module_c_memory"

trance-analyze.exe --case demo --evidence-dir evidence \
    --onion <address>.onion --host 127.0.0.1:5000 --username alice
```

`trance-analyze` reads `acquire_manifest.json` to resolve each artifact's
path automatically; any explicit flag (`--ntuser`, `--dump`, ...) always
overrides auto-discovery. `--disk-image`/`--disk-root` are never
auto-discovered (a raw image or a mounted volume isn't something
`acquire_all.py` produces) — pass them explicitly, same as with `main.py`.
It's a thin wrapper around `main.py` — same
`findings.json`/`report.html`/`custody.json` output, same targeting/
`--vol3-*` flags. `--vol3-path` still needs Volatility3 installed
separately on the examiner's `PATH` (it's shelled out to, never bundled —
avoids Volatility3's dynamic plugin-loading being a PyInstaller risk).
Neither exe needs a Python install on its machine; both are still
`--onefile` binaries and may need AV allowlisting as noted above.

`--collect-all tzdata` is required, not optional: Windows has no OS-level
timezone database, so Python's `zoneinfo` (used by `--report-timezone`
and the auto-detected local time in every report) depends entirely on
the `tzdata` PyPI package's data files. PyInstaller's default import
analysis only follows `.py` code, not `tzdata`'s ~600 non-code zone
files, so without this flag every zone name — typed or auto-detected —
silently fails to resolve in the built exe even though it worked fine
from source.

### Desktop GUI (`trance-gui`)

`gui_main.py` is a PySide6 desktop app over the same backend — Analyse
(pick an evidence folder, run, progress bar), Report (embeds the same
`report.html` the CLI produces, in a `QWebEngineView` — no separate
presentation logic to maintain), History (lists past cases by scanning
`<output-dir>/*/findings.json`, same "filesystem is the source of
truth" convention `analyze_evidence.py` already uses, not a second
store to keep in sync). It's an additional way to drive `main.py`'s
pipeline, not a replacement for `trance-analyze` — both stay available.
The Analyse tab's target options take the host, a username, the target's
cookie names and the report time zone.

Kept out of `requirements.txt` on purpose — `requirements-gui.txt`
(`PySide6`) is separate so `trance-acquire`/`trance-analyze` builds stay
exactly as lean as before:

```
pip install -r requirements.txt -r requirements-gui.txt pyinstaller
pyinstaller --onefile --name trance-gui gui_main.py \
    --hidden-import modules.module_a_registry \
    --hidden-import modules.module_b_disk \
    --hidden-import modules.module_c_memory \
    --collect-all PySide6 \
    --collect-all tzdata \
    --add-data "report_template.html.j2:." \
    --add-data "modules/module_c_memory/report_template.html.j2:modules/module_c_memory"

trance-gui.exe --output-dir output
```

(`;` instead of `:` for `--add-data` on Windows, same as `trance-analyze`.)
The GUI needs `requirements.txt` too, not just `requirements-gui.txt` —
it drives `main.py`'s full pipeline (regipy, jinja2, tzdata, ...), not
just PySide6, and `--collect-all tzdata` is needed for the same reason
noted under `trance-analyze` above. `--collect-all PySide6` is needed for `QtWebEngine`'s own resources/
plugins. Expect a noticeably larger binary than the other two exes —
QtWebEngine bundles a Chromium build (built and smoke-tested in this
repo at ~290MB `--onefile`, vs. ~15MB for `trance-analyze`); this is the
tradeoff of embedding the report view instead of a lighter web
framework. Same AV-allowlisting note as the other `--onefile` exes.

### Building the acquisition EXE from the GUI

The desktop app's **Build EXE** tab automates the manual
`pyinstaller --onefile --name trance-acquire acquire_all.py` step from
above, so you don't need a terminal to produce the file you carry to the
target machine:

1. Open the GUI (`python gui_main.py`) and switch to the **Build EXE** tab.
2. Click **Generate acquisition EXE**. If PyInstaller isn't installed, or
   the interpreter running the GUI isn't 64-bit, you'll get a clear message
   instead of a broken build — install it with
   `pip install -r requirements-dev.txt` and retry.
3. Choose where to save the resulting `.exe` in the save dialog.
4. Watch the live build log; **Cancel** stops the build at any point.
5. On success, the tab shows the saved path and an **Open folder** button.

The build runs entirely inside a temporary directory (never inside the
repo) and embeds a UAC manifest (`--uac-admin`), so the exe itself
prompts for Administrator elevation when launched on the target — no
manual "Run as Administrator" step is required. Copy the single `.exe` to
the target machine (USB stick, network share) and run it there, e.g.:

```powershell
E:\trance-acquire.exe --output-dir E:\evidence
```

WinPMEM is **not** bundled into the exe — it's deliberately kept
examiner-supplied, same as a manually built `trance-acquire.exe`: pass
`--winpmem-path`, or let `winpmem_acquire.py`'s auto-discovery find a
`*winpmem*.exe` already on the target machine.

### Limitation: process memory dies with the process

Live acquisition must happen while `firefox.exe` is still running —
once it exits, its process memory is gone and there is nothing left for
`dumper.py` to read. Recovering browser traces from an already-exited
process uses a full physical-RAM capture instead (`trance-acquire` runs
WinPMEM, examiner-supplied, whether or not Tor Browser is open), analysed
with `--source-type full-memory`; Volatility 3 (`--vol3-path`) can narrow
that image to one process. A full image taken *after* the browser closed still
held part of the session, but far less than one taken while it was open --
see *Evaluating the tool*.

## Evaluating the tool

`scripts/score_run.py` measures a run against a session whose contents are
known. A scripted Tor Browser session (a control onion site that logs every
request, so the ground truth is exact) is captured four ways -- powered off,
running with the browser closed, running with it open, and a negative control
with no browsing -- and each capture is scored:

```
python scripts/score_run.py score --ground-truth ground_truth.json \
    --server-gt <run>.json --findings output/<case>/findings.json \
    --run-id c4-r01 --condition C4 --baseline <evidence folder>
python scripts/score_run.py aggregate results/
```

It reports recall (items recovered / items performed), planted decoys that
appear in the findings, and -- with `--baseline` -- a plain case-insensitive
byte search of the same evidence, so a miss by the tool can be told apart from
something that was never captured. The negative control must report none of the
planted strings.

Results from one run per condition (37 scored items): with the browser open
every item was present in RAM and the improved tool recovered all 37 (the
original tool: 22); after the browser closed, 8 items remained in RAM and 7
were recovered; on a powered-off disk only 7 were present and 6 recovered.
These are single runs, and the extractors that closed the gap were developed on
the same capture, so confirm on a fresh run before quoting the 37/37. The full
method, deviations and limits are in `CLAUDE.md` (section 10).

## Module B — preserve evidence during profile analysis

Run the profile analyzer against a **static extracted acquisition**, with its
`hashes.sha256` manifest and SQLite `-wal` / `-shm` companions kept in their
original relative directories:

```sh
python -m modules.module_b_disk.recover_evidence /path/to/acquired/profile \
    --output-dir output/module-b
```

Each run creates a new timestamped directory containing `recovery_report.json`
and `recovery_report.custody.json`. `--out /path/to/new/report.json` selects an
explicit report path instead. Both outputs must be outside the evidence tree;
existing outputs are refused. The same protected profile analysis is used when
the directory is supplied to `main.py` with `--disk-profile`.

Before parsing, the analyzer verifies SHA-256 manifest entries using their full
relative paths (standard `sha256sum` text or binary format). Missing files,
malformed/duplicate entries, unsafe paths, symbolic links, and mismatches stop
the run. WAL and SHM mismatches are treated as failures too. Without a manifest,
analysis proceeds with `manifest_status: absent`; newly computed hashes do not
establish acquisition-time integrity. Files absent from a supplied manifest are
listed separately as `unmanifested_files`.

The analyzer hashes the source tree, makes and verifies a disposable working
copy, and checks source hashes again after analysis. SQLite queries operate on
temporary copies with their WAL/SHM companions, preserving committed WAL data.
Custody records identify original paths and hashes, plus the generated report.
Use an offline, read-only acquisition: these content checks do not provide a
filesystem write blocker, preserve access times, or authenticate the manifest.

Exit codes: `0` analysis completed, `1` integrity/output/input failure, `2`
incomplete analysis due to missing or unreadable artifacts. Check the report's
per-artifact errors; incomplete input is not evidence of no browsing activity.
The daemon and raw-carving standalone scripts are not covered by this profile
snapshot workflow yet.
