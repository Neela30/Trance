# TRANCE — Context for Claude sessions

Progress log for the memory-forensics work (Module C). Read this before picking the task back up.

## Repo orientation

- Team repo: `https://github.com/Neela30/Trance.git`. Remote branches: `main`, `memory`, `Neela`, `Sahe`, `Thila`.
- **Work lives on branch `memory`**, not merged to `main` yet. `main` does NOT have `modules/module_c_memory/*` code.
- Layout: `core/` (shared dataclasses/utils — config, custody_log, exceptions, hashing, schema), `modules/module_a_registry`, `modules/module_b_disk`, `modules/module_c_memory` (registry/disk modules are still empty `__init__.py` stubs — nobody's written that code yet, despite README describing a 3-module pipeline).
- Python ≥3.10, setuptools (`pyproject.toml` + `setup.cfg`), black/ruff line-length 100, deps split `requirements.txt` / `requirements-dev.txt`.

## What's built (Module C — memory forensics)

Two tools in `modules/module_c_memory/`, split acquire vs. analyze because live process memory only exists while the process is alive:

- **`dumper.py`** — Windows-only, needs admin. Finds the `firefox.exe` process with the largest RSS, dumps its readable committed memory via `ctypes` (`OpenProcess`+`VirtualQueryEx`+`ReadProcessMemory`, no procdump/pywin32). Writes `<name>.bin` + `<name>.bin.sha256` sidecar + a `core.custody_log` JSON entry. Raises `core.exceptions.AcquisitionError` with a clear message if `OpenProcess` fails (not elevated). Only external dep: `psutil`.
- **`analyzer.py`** — pure stdlib, runs anywhere, offline, against a saved `.bin`. Chunked string extraction (ASCII + UTF-16LE, handles multi-GB files). Reports **host-anchored**: URLs containing `--onion`/`--host` only, exact-name cookies (`session=`, `trance_user=`, `trance_pref=`), `?q=` search queries (flags matches against `--username`), and `username=`/`password=` credential shapes (requires literal `=`+value, so it does NOT false-positive on things like `Pass::draw_indexed` or `LoginManager.sys.mjs` — verified with a synthetic dump containing exactly those as negative controls). Separate "unfiltered" section (counts + capped samples) labelled noisy. Verifies dump integrity against the `.sha256` sidecar if present (raises `IntegrityError` on mismatch). Emits JSON report (`<dump>.report.json`, using `core.schema.Artifact` for findings) + readable stdout summary. All three targeting flags (`--onion`, `--host`, `--username`) are optional — need at least one of onion/host or the targeted-URL section stays empty (analyzer just warns).

Reused existing `core/` conventions rather than reinventing: `core.hashing.hash_file`, `core.custody_log.CustodyLog/CustodyEntry`, `core.exceptions.AcquisitionError/ParsingError/IntegrityError`, `core.schema.Artifact`.

**Corrected a README overclaim**: it previously said the memory module already used Volatility3+YARA — it doesn't (that's future work, deps already sit unused in `requirements.txt` for that reason). Fixed the wording, added a full "Module C" README section (acquire cmd, analyze cmd, PyInstaller onefile build cmd + AV-flagging note, and a limitation note: live acquisition only works while `firefox.exe` is running — full physical-RAM capture via WinPMEM is the path to recovering an already-exited process, noted as future work, not implemented).

## Verified so far

- Both files `py_compile` clean. `dumper.py`'s `ctypes.wintypes` import is guarded behind `sys.platform == "win32"`, so it imports fine on Linux (just refuses to run there).
- Built a synthetic `.bin` locally and ran `analyzer.py` against it: target URL/cookies/query/creds all extracted correctly with byte-exact offsets (caught and fixed a real bug — nested regex matches were reporting the *containing string's* offset instead of their own; fixed). Negative controls confirmed no false positives. Integrity check tested both valid-sidecar and corrupted-sidecar paths.
- `dumper.py` itself is untestable on this (Linux) dev machine — Windows-only API. Structurally matches documented WinAPI signatures but hasn't been exercised for real until the VM run below.

## VM test run (in progress)

- Windows VM, Tor Browser installed, VirtualBox shared folder `\\VBOXSVR\trance` set up for file transfer (**never confirmed actually reachable** — copy attempts failed on a missing source path before the destination was ever tested; revisit this).
- VM didn't have `winget` (image doesn't ship App Installer) — installed Git for Windows manually instead (direct download).
- Cloned repo on VM to `C:\forensics\TRANCE` via `git clone -b memory https://github.com/Neela30/Trance.git`.
- Hit a module-path snag: `python -m modules.module_c_memory.dumper` got mangled to `modules.module_c_memory_dumper` (dot turned into underscore) when pasted — suspected VirtualBox clipboard corruption. Fixed by typing the command manually.
- **Dumper ran successfully against live Tor Browser on the VM** — dump completed.
- Decided to run `analyzer.py` directly on the VM this round too (fine — it's read-only stdlib, no admin needed) instead of transferring the `.bin` first.

## Open items / next steps

- Copy the `.bin`+`.sha256`+`.custody.json` off the VM for repeated offline re-analysis (the intended workflow — analyze locally with different `--onion`/`--host`/`--username` targeting without re-touching the VM). Still unresolved whether `\\VBOXSVR\trance` actually works.
- Run the PyInstaller `--onefile` build on Windows to produce `trance-memdump.exe` (documented in README, not yet executed).
- `module_a_registry` and `module_b_disk` are still unimplemented stubs — presumably other teammates' branches (`Neela`, `Sahe`, `Thila`).
- `memory` branch not yet merged to `main` / no PR opened.

## Analyzer fixes (2026-09-04, driven by real gaps in `firefox_5368_20260904T050334Z.bin.report.json`)

The first real VM report exposed 4 analyzer gaps, all fixed in `analyzer.py`:

1. **Missing --onion this run**: `targeted.urls` came back empty because the analyze command only passed `--host 127.0.0.1:5000`, not `--onion`. The onion address was all over the unfiltered sample, never anchored. Fixed the symptom generically: added `ONION_DOMAIN_RE` + a `targeting_suggestions` field — if an onion domain shows up ≥3x in memory and isn't covered by the `--onion`/`--host` given, the report now surfaces it with a suggested re-run command. Doesn't replace passing the right flag, just makes the gap visible instead of silently empty.
2. **Credentials regex too narrow**: old `CREDENTIAL_RE` only matched literal `username=value`/`password=value` (form-encoded, 2 field names). Broadened to `CREDENTIAL_FIELDS = user|username|uname|login|email|password|passwd|pwd` and added `CREDENTIAL_JSON_RE` for `"field":"value"` JSON bodies. Kept case-sensitive lowercase-only on purpose — case-insensitive would start matching Windows env-var dumps (`USERNAME=<os user>`) and C++/JS identifiers (`Pass::draw_indexed`, `LoginManager.sys.mjs`) that were deliberately used as negative controls when this analyzer was first built.
   - Caveat found while diagnosing: in the VM report, the actual typed strings (`sunimalaya`, `icekaraya`) never appear as `field=value` or JSON anywhere in the dump — they only showed up via the `?q=` pattern (Tor Browser's urlbar sends typed text to the default search engine). That means the target app's login POST either wasn't in a text-matchable shape in this dump, or the region got overwritten/paged before capture. Broadening the regex doesn't retroactively recover that — it only helps *future* dumps if the app's actual wire format matches one of the new shapes. Worth revisiting with `--username` set on re-analysis so at least the `matches_username` flag lights up on the existing search-query hits.
3. **No download detection at all**: added `FILE_URI_RE` (`file:///...`) and `DOWNLOAD_PATH_RE` (Windows path under `Users`/`Downloads` ending in a common file extension) → new `download` artifact type, always collected (not host-anchored, like credentials).
4. **Real session/cookie hits buried in Firefox's own printf-format-string noise** (`session=%p`, `session=a`, etc. — literal format strings compiled into the binary that happen to match the same exact-name regex): added `_is_noise_value()` (flags values starting with `%` or ≤2 chars) → every cookie/credential entry now carries a `confidence: high|low` tag, and a new top-level `key_findings` block dedupes+counts only the high-confidence hits so they don't have to be eyeballed out of a 24-entry list by hand.

`format_summary()` now prints `KEY FINDINGS` (deduped, high-confidence, plus any targeting suggestion) before the full noisy detail section, instead of one flat list per category.

**Not yet validated against a real dump** — couldn't `py_compile` or exercise this in the session that wrote it (sandboxed environment's safety check blocked all `python3` invocations after the conversation discussed the real captured session token, unrelated to the code itself). Reviewed by eye only. Next session: get the actual `.bin` off the VM (see item above) and re-run `analyzer.py` against it — both to sanity-check the new regexes/dedup logic and to regenerate the report with `--onion krf3io7j4x5hbzhyi5hnbwr4cocnya5ri3mg3k3sqt7xucmpkeztjvad.onion --username <actual test username>` so item 1 above stops being empty for real.

## Quick reference

```
# Dump (Windows VM, elevated shell, Tor Browser open)
python -m modules.module_c_memory.dumper --output-dir captures

# Analyze (any machine, offline)
python -m modules.module_c_memory.analyzer captures\firefox_<pid>_<ts>.bin --host 127.0.0.1:5000 --onion <addr>.onion --username <user>
```
