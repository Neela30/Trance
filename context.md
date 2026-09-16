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

**Update (same day)**: re-ran against the real VM dump (`firefox_5368_20260904T050334Z.bin`, copied to `vm-shared/`). Confirmed the fix — full 12-path site map recovered, clean admin session token, real downloads matched to `/download/` hits. Also found and fixed one more false-positive: the download-path matcher was flagging Firefox's own UI icons (`.../skin/.../downloads/downloads.svg` — "downloads" as a literal path segment, not the Windows special folder) as confirmed downloads. Tightened `_DOWNLOADS_DIR_RE` to require the full `Users\<name>\Downloads\` shape.

**Added `report.py` + `report_template.html.j2`** — deterministic, offline HTML report rendering, no LLM/API involved anywhere (this was a deliberate choice after discussing it: a memory dump is evidentiary, a fixed auditable rule beats a model's judgment call). Wired into `analyzer.py` via `--html-report PATH`. First real use of `jinja2`, which had sat unused in `requirements.txt` since the initial commit. Generalizes what was manually written up in a one-off case report: clean site-map extraction (`urllib.parse`), near-duplicate path flagging (`difflib.get_close_matches` — catches typo/probe variants like `/favicon.ico` vs `/favicon.icox` generically, not hardcoded), a generic base64url-JSON session-token decoder (not tied to this app's token shape), download-to-endpoint correlation by filename, and the two offset-based interpretive callouts (page-clustering, cookie-storage-region) as fixed distance-threshold rules (`CLUSTER_GAP_BYTES`, `FAR_FROM_START_MULTIPLIER` — tune per-case if a dump doesn't fit). Not yet run for the same reason as above — reviewed by eye only.

## Pipeline restructure (2026-09-04, later the same day)

Findings + report generation moved to the repo root and generalised across modules:

- `core/schema.py` — added `ModuleResult(module, status, artifacts, details, message)`; the contract every module's `run()` returns. Statuses: `ok` / `skipped` / `not_implemented` / `error`.
- `modules/<name>/__init__.py` — each now exposes `run(config, **kwargs) -> ModuleResult`. A and B are honest `not_implemented` stubs (teammates' branches own the real code). C wraps `analyzer.analyze()`; `skipped` if no `--dump`; pops `artifacts` out of the analyze dict into `ModuleResult.artifacts` so findings.json doesn't duplicate them.
- `findings.py` (root) — `build_findings(config, results)` / `write_findings()` / `load_findings()`. Schema documented in its docstring: per-module `status`/`message`/`artifact_count`/`details`, plus one flattened cross-module `artifacts` array.
- `report.py` (root) — `render_report(findings)` / `write_report()`. Owns the Jinja2 env and `report_template.html.j2` (root). Module-specific presentation is looked up in `PRESENTERS`; anything else gets a generic artifact table + status.
- `modules/module_c_memory/report.py` — **repurposed**, no longer renders. Now `build_context(details) -> dict` (site map, near-dup paths, token decode, download↔endpoint match, timeline flags). Same filename because `git rm`/`git mv` were blocked in the session that did this (same safety-check block as `python3`); it kept the name rather than leaving a dangling duplicate.
- `main.py` (root) — CLI orchestrator. `--case` (required), `--output-dir` (default `output/`), `--evidence-dir`, `--verbose`, plus module C's `--dump/--onion/--host/--username`. Imports each module via `importlib` inside try/except so a Windows-only import on a teammate's branch can't kill the run on Linux. Writes `findings.json`, `report.html`, `custody.json` (uses `core.custody_log` — entries for the dump analyzed + both outputs). Exit 2 if any module errored.
- `analyzer.py` — dropped the `--html-report` flag; standalone run is JSON + stdout only, HTML comes from `main.py`.
- `.gitignore` — added `/output/` (real-evidence findings/reports must never be committed, same rule as `/captures/`).

**First real `main.py` run showed the site map full of junk** — two extractor problems, fixed in `analyzer.py`: (1) `URL_RE`/`ONION_RE` trailing charset swallowed Firefox cache/principal key syntax (`<host>,p,:http://…`, `^privateBrowsingId`, `:0|<hash>`), so each cache key became a fake URL; now both stop at `, ^ | ] ) }`, and a scheme-less onion only counts with a `/path` (bare domain = mention, not visit; onions inside a full URL span are skipped so search-engine `?q=<onion>` lookups don't double as visits). (2) Target matching was substring-anywhere; now `_matches_target()` is host-anchored (`urls` entries carry `host`/`path`/`asset`). Also: asset loads (`ASSET_EXTENSIONS`) are split out of the site map and activity sequence, `is_timeline_noise()` drops "mozilla" strings and anything with <3 alphanumerics, timeline page visits key on host+path so schemed/scheme-less forms collapse, and near-dup path flagging in module `report.py` is 0.9 ratio + ≤2 length diff, compared against assets too (so `/favicon.icox` still catches against `/favicon.ico`).

**Leftover to clean up by hand**: `modules/module_c_memory/report_template.html.j2` is now unused (root template replaced it) but couldn't be deleted in-session — `git rm modules/module_c_memory/report_template.html.j2`.

**Still not executed** — same session block. Next session: `python main.py --case vm-run-1 --dump ../vm-shared/firefox_5368_20260904T050334Z.bin --onion krf3io7j4x5hbzhyi5hnbwr4cocnya5ri3mg3k3sqt7xucmpkeztjvad.onion --host 127.0.0.1:5000 --username sunimalaya` from the repo root, fix whatever breaks, then commit.

## Stale-fact correction (2026-09-11)

A few things above are now outdated (confirmed by re-exploring the repo this session, branch `Sahe`):

- Line 9's "`module_b_disk` is an empty stub" is **no longer true** — Sahe (commits `abbb01c`, `35f458f`, 2026-09-09) wrote real code: `evidence.py` (hash-verified working-copy handling), `recover_evidence.py`, `analyze_tor_datadir.py`, `carve_onion_strings.py`. Each is its own `argparse` CLI writing its own JSON + `.custody.json`; `modules/module_b_disk/__init__.py` is still the `not_implemented` stub, so none of it is wired into `main.py` yet.
- The "still not executed" `main.py` run (line 80) **has since been run** — `output/vm-run-1/{findings.json,report.html,custody.json}` exists (2026-09-04), with the follow-up fixes from commit `951bdfd`. This log was never updated to say so.
- `modules/module_c_memory/report_template.html.j2` (line 78) is **still not removed** — `git rm` it when next touching this area.
- Found separately: `output/vm-run-1/report.html` on disk (sha256 `81b188bb…`) no longer matches what the current code renders from the stored `findings.json` (sha256 `2b901cc4…`, which is what `custody.json` actually recorded) — someone hand-edited the HTML afterward to swap 5 real search-query values (`sunimalaya`, `icekaraya`) for sanitized placeholders before sharing it. Worth knowing: that file's custody hash no longer verifies, and `findings.json` still has the real values.

## Post-mortem acquisition — design (2026-09-11)

The standing limitation (`dumper.py` needs a *live* `firefox.exe`) is being addressed. User's direction: VirtualBox is only the test harness — host-side VM tricks (`VBoxManage debugvm dumpvmcore`) are explicitly **out of scope**; the design must work on real Windows hardware. Three acquisition sources chosen: **WinPMEM** (full physical RAM, live, admin+driver), **`pagefile.sys`**, **`hiberfil.sys`** — plus **Volatility3** for analysis (already declared in `requirements.txt`, never installed until now).

Key design fact driving everything: **Volatility3 cannot reconstruct an exited process's address space** (page tables/VAD torn down at exit — `windows.memmap --pid` yields nothing). What it *does* give for an exited process: `windows.psscan` finds the residual `_EPROCESS` pool allocation (proves existence, PID/PPID, CreateTime/**ExitTime**) until that pool memory is reused, plus system context (`cmdline`, `netscan`, `filescan`, `hivelist`). The actual *content* — URLs, cookies, search queries — lives in freed physical pages, unattributed to any process, and is only recoverable by the existing string carver. **Volatility3 and `analyzer.py` are complementary** (provenance + context vs. content), not alternatives — the eventual report must say so plainly rather than implying Volatility hands back the dead browser's heap.

Locked-file problem (`pagefile.sys`/`hiberfil.sys` can't be plain-copied): planned primary is raw NTFS extraction via an examiner-supplied external tool (RawCopy/TScopy, opens `\\.\C:` directly, bypasses the OS lock) — no new Python dependency. `esentutl /y /vss` is a documented fallback but likely fails for pagefile specifically (Windows commonly excludes paging files from shadow copies) — needs runtime verification on a real target, not assumed. Full design (acquisition scripts, Volatility3 plugin mapping, symbol/offline handling, hibernation-support uncertainty, provenance/evidentiary-weight modelling for pagefile vs. RAM vs. hibernation vs. live-process-dump findings, `main.py` wiring) is written out in full at `~/.claude/plans/alright-currently-the-main-sprightly-creek.md` — read that before starting Phase 2+.

User said to implement **Phase 1 only** for now (see next section) and hold off on acquisition scripts / Volatility3 / report wiring.

## Phase 1 done (2026-09-11) — `analyzer.py` hardened for whole-system-image scale

Two real problems with feeding `analyzer.py` a multi-GB physical-RAM image or pagefile instead of a single process dump, both fixed:

1. **`iter_strings()`'s `seen_offsets: set[int]`** was unbounded — fine for the existing 537 MB process dump, not fine at 8–16 GB. Replaced with a per-pattern high-water-mark int (`ascii_floor`/`utf16_floor`): `finditer()` yields strictly increasing offsets within a window, and the only cross-window duplicates are re-scans of the `OVERLAP` carry region, so `abs_off > floor` is exactly equivalent to `abs_off not in seen_offsets` for this access pattern — O(1) memory instead of O(matches).
   - **Verified, not assumed.** True before/after diff (pre-edit analyzer loaded via `importlib` from `git show HEAD:...`, both run against the real `/home/thilakshan/Documents/Projects/cysec-project/vm-shared/firefox_5368_20260904T050334Z.bin` with the same targeting the committed report used): every derived field — `targeted.{urls,cookies,search_queries,credentials,downloads}`, `key_findings`, `timeline`, `artifacts` — came back **byte-identical**. Only `unfiltered.total_strings_extracted` differs, by 4 out of 1,919,057 (0.0002%) — a boundary-dedup edge case in the overlap region that affects zero actual findings, present in both old and new logic's neighborhood, not a regression.
   - **Peak RSS measured** (`/usr/bin/time -v`, same 537 MB dump): 454,052 KB → 384,740 KB, ~15% lower. Gets more pronounced the bigger the image gets, since the old cost scaled with match count, not file size.
2. **Unbounded per-category result lists** — added `MAX_RECORDS_PER_TYPE = 50_000`, enforced via a new `append_capped()` helper wrapping every `urls`/`cookies`/`search_queries`/`credentials`/`downloads`/`artifacts` append site. A capped category is recorded in a new top-level `report["truncated"]: dict[str, bool]`, and `format_summary()` prints a `[!] Result cap (50,000/type) hit — truncated: ...` line when non-empty. Also capped `onion_domain_hits` (only ever used for the top-10 `targeting_suggestions`) to `most_common(1_000)` once it exceeds 10,000 distinct keys.
   - **Verified**: synthetic 10-URL dump with `MAX_RECORDS_PER_TYPE` monkeypatched to 3 → exactly 3 `urls`/`artifacts` returned, `truncated == {"urls": True, "artifacts": True}`, warning line present in `format_summary()` output.

Not started at the time this section was written: acquisition scripts for WinPMEM/pagefile/hiberfil, Volatility3 integration, provenance modelling in the report, `main.py`/`report.py`/template wiring for multi-source runs. **WinPMEM acquisition and Volatility3 integration are both done now — see the two sections below.** pagefile.sys/hiberfil.sys extraction is still not started.

## WinPMEM full-memory acquisition (2026-09-16, commit `f9f4511`)

Added `modules/module_c_memory/winpmem_acquire.py` — Windows-only, admin-required, shells
out to an examiner-supplied WinPMEM binary (`--winpmem-path`; not vendored, same pattern
as RawCopy/TScopy in the pagefile/hiberfil design above) to capture a full physical-memory
`.raw` image, hash it, sidecar it, and log it — same pattern as `dumper.py`'s process
dumps. `analyzer.py` gained a `source_type: process|full-memory` parameter (`--source-type`
on its CLI and `main.py`) that's pure provenance/threshold labeling — it raises the
per-category result cap for full-memory images (`SOURCE_TYPE_RECORD_CAPS`, 50k → 200k) and
records which acquisition path produced the analyzed file, but never invokes either
acquisition tool itself. `module_c_memory/__init__.py::run()` stays "analyze an existing
--dump" only, by design — see that file's docstring for why auto-invoking Windows-only
acquisition from an otherwise offline analysis entrypoint was deliberately not done.

## Volatility3 structural analysis (2026-09-16, 4 commits)

Added a second, independent analysis pass alongside the string carver:

- **`modules/module_c_memory/volatility_analyze.py`** — thin subprocess wrapper around
  the `vol` CLI (`vol -q -f <image> -r json <plugin>`), not Volatility3's internal
  framework API. Runs `windows.psscan.PsScan`, `windows.netscan.NetScan`,
  `windows.filescan.FileScan`, `windows.cmdline.CmdLine`,
  `windows.registry.hivelist.HiveList` — each independently; one plugin's failure
  (typically: no symbol table matching the imaged OS build) is recorded and doesn't
  abort the rest. Only a genuinely unreachable `vol` binary or missing image raises
  `core.exceptions.AnalysisError` (new — narrowly scoped, not reusing `AcquisitionError`
  since this is an analysis-time failure, not an acquisition-time one). Every row is
  tagged `"source": "volatility3:<plugin>"` so it can never be confused with a
  string-carver finding downstream.
- Actually installed `volatility3` (2.28.0, previously in `requirements.txt` unused since
  the initial commit — bumped to `>=2.26.0` as the tested floor) to verify this against a
  **real** `vol` CLI, not guessed. Two things only a real run caught:
  1. **`windows.hivelist` is not a valid plugin name** in 2.28.0 — it's
     `windows.registry.hivelist.HiveList` (moved under a `registry` sub-namespace at some
     point). The design doc's plugin list (line ~93 above) has the old short name; the
     actual code uses the fully-qualified one.
  2. Exit-code/output-shape behavior isn't obvious from docs alone: `vol` exits 1 (not 0)
     when a plugin's symbol/layer requirements aren't met, error text goes to *both*
     stdout and stderr, and there's no JSON on stdout at all in that case — confirmed by
     running against a 1 MB `/dev/urandom` file with all 5 plugins. The wrapper treats a
     non-zero exit OR a JSON-parse failure as "this plugin didn't run," never a crash.
  3. Pulled the exact `TreeGrid` column names for all 5 plugins straight from the
     installed package source (`volatility3/framework/plugins/windows/{psscan,netscan,
     filescan,cmdline,registry/hivelist}.py`) rather than assuming — e.g. psscan is
     `PID/PPID/ImageFileName/Offset{V,P}/Threads/Handles/SessionId/Wow64/CreateTime/
     ExitTime/File output`, netscan is `Offset/Proto/LocalAddr/LocalPort/ForeignAddr/
     ForeignPort/State/PID/Owner/Created`. These are what the report's corroboration
     logic keys off.
- **`modules/module_c_memory/__init__.py::run()`** gained a `vol3_path` parameter
  (`--vol3-path` in `main.py`, opt-in — omitted means the whole pass is skipped). Merged
  into `details["volatility3"]` as its own top-level key, never interleaved into the
  string-carver's `targeted`/`key_findings` categories. Degrades cleanly: no path given,
  or `vol` unreachable, both land in `details["volatility3"]["status"] ==
  "skipped"/"error"` without touching the module's own `ok` status — the string-carver
  path keeps working independently of whether Volatility3 is installed at all.
- **Report**: new "Process & system context (Volatility3)" section in
  `report_template.html.j2`, fed by `_vol3_context()` in `modules/module_c_memory/
  report.py`. Per-plugin tables driven directly off each row's own keys (no hardcoded
  column list to keep in sync). Corroboration is deliberately plain-text juxtaposition,
  not a scoring engine, per the task spec: a psscan row whose `ImageFileName` is
  `firefox.exe` gets a note that structural evidence agrees a browser process existed; a
  netscan row matching `--host` gets a note it saw that connection independently; a
  filescan row whose filename matches an already-confirmed `\Downloads\` hit gets a note
  they match. All three verified against synthetic Volatility3-shaped row data (a real
  successful plugin run needs actual Windows kernel symbols + a real Windows image,
  neither available in this environment — see below).

**Still unverified, same reason as the WinPMEM section above**: no real Volatility3
plugin run against a real Windows memory image in this session — only against a junk
1 MB file (confirms invocation/argument/error-handling correctness, not real output
parsing) and hand-built synthetic JSON matching the real `TreeGrid` schemas (confirms
report/corroboration logic, not that Volatility3 itself will actually produce that shape
against a real capture). The existing real dump (`firefox_5368_20260904T050334Z.bin`) is
a single-process dump, not a full-system image most `windows.*` plugins expect, so even
once a Windows box is available, that specific file likely won't exercise this well —
next real validation should pair a `winpmem_acquire.py` full-memory image with a real
Volatility3 run on Windows or against a copied-off image with correct symbols.

## Quick reference

```
# Dump a live process (Windows VM, elevated shell, Tor Browser open)
python -m modules.module_c_memory.dumper --output-dir captures

# OR: full physical-memory capture (Windows, elevated, WinPMEM binary supplied by examiner)
python -m modules.module_c_memory.winpmem_acquire --winpmem-path C:\tools\winpmem.exe --output-dir captures

# Analyze the string-carve pass alone (any machine, offline)
python -m modules.module_c_memory.analyzer captures\firefox_<pid>_<ts>.bin --host 127.0.0.1:5000 --onion <addr>.onion --username <user> --source-type process

# Full pipeline incl. Volatility3 structural pass (any machine, offline; --vol3-path opt-in)
python main.py --case demo --dump captures\fullmem_<ts>.raw --host 127.0.0.1:5000 --source-type full-memory --vol3-path vol
```
