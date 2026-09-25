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

### Module contract

Each `modules/<name>/__init__.py` exposes

```python
def run(config: core.config.TranceConfig, **kwargs) -> core.schema.ModuleResult
```

returning `ModuleResult(module, status, artifacts, details, message)` where
`status` is one of `ok` / `skipped` / `not_implemented` / `error`,
`artifacts` is a list of `core.schema.Artifact`, and `details` is any
module-specific dict worth keeping verbatim in `findings.json`. Module-specific
CLI flags are declared in `main.py` and passed through as `kwargs`. To
contribute a custom section to the HTML report, register a presenter in
`report.py`'s `PRESENTERS`; without one a module gets a generic artifact table.

Module A (registry) currently returns `not_implemented`. Module B runs when at
least one disk evidence path is supplied and otherwise returns `skipped`.

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
    --username alice
```

- `--onion` / `--host` anchor URL matching to the target hidden service —
  without at least one of these the targeted-URL section is empty.
- `--username` highlights recovered search queries (`?q=<value>`) that
  match a known test user.
- Reports, host-anchored: target URLs only; the exact application cookies
  (`session=`, `trance_user=`, `trance_pref=`); search queries; and
  form-submission credential shapes (`username=<value>`,
  `password=<value>` — requires an `=` and a value, so it does not match
  bare code identifiers such as `Pass::draw_indexed` or
  `LoginManager.sys.mjs`).
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

### Desktop GUI (`trance-gui`)

`gui_main.py` is a PySide6 desktop app over the same backend — Analyse
(pick an evidence folder, run, progress bar), Report (embeds the same
`report.html` the CLI produces, in a `QWebEngineView` — no separate
presentation logic to maintain), History (lists past cases by scanning
`<output-dir>/*/findings.json`, same "filesystem is the source of
truth" convention `analyze_evidence.py` already uses, not a second
store to keep in sync). It's an additional way to drive `main.py`'s
pipeline, not a replacement for `trance-analyze` — both stay available.

Kept out of `requirements.txt` on purpose — `requirements-gui.txt`
(`PySide6`) is separate so `trance-acquire`/`trance-analyze` builds stay
exactly as lean as before:

```
pip install -r requirements-gui.txt pyinstaller
pyinstaller --onefile --name trance-gui gui_main.py \
    --hidden-import modules.module_a_registry \
    --hidden-import modules.module_b_disk \
    --hidden-import modules.module_c_memory \
    --collect-all PySide6 \
    --add-data "report_template.html.j2:." \
    --add-data "modules/module_c_memory/report_template.html.j2:modules/module_c_memory"

trance-gui.exe --output-dir output
```

(`;` instead of `:` for `--add-data` on Windows, same as `trance-analyze`.)
`--collect-all PySide6` is needed for `QtWebEngine`'s own resources/
plugins. Expect a noticeably larger binary than the other two exes —
QtWebEngine bundles a Chromium build (built and smoke-tested in this
repo at ~290MB `--onefile`, vs. ~15MB for `trance-analyze`); this is the
tradeoff of embedding the report view instead of a lighter web
framework. Same AV-allowlisting note as the other `--onefile` exes.

### Limitation: process memory dies with the process

Live acquisition must happen while `firefox.exe` is still running —
once it exits, its process memory is gone and there is nothing left for
`dumper.py` to read. Recovering browser traces from an already-exited
process requires a full physical-RAM capture taken before shutdown (e.g.
WinPMEM) and analysis with a memory-forensics framework such as
Volatility 3 (already declared in `requirements.txt` for this reason).
That path is future work and is not implemented here.

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
