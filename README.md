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
  on stdout.

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
