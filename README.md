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

# Add this to find downloaded files anywhere on the volume (mounted read-only
# via ntfs-3g, e.g. qemu-nbd + mount -o ro). Every file carrying a
# Zone.Identifier stream is reported with its NTFS creation time and flagged
# as inside/outside the Tor daemon's last active window when --tor-dir is
# also given. Tor Browser strips the source URL from that stream by design,
# so this establishes network origin and timing, never the originating site:
#   --disk-root /mnt/evidence-volume
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
