"""TRANCE entry point: run every module, merge into findings.json, render report.html.

    python main.py --case demo --output-dir output \\
        --dump captures/firefox_<pid>_<ts>.bin \\
        --onion <address>.onion --host 127.0.0.1:5000 --username alice

Writes <output-dir>/<case>/findings.json, report.html and custody.json.

Modules run in a fixed order and are isolated from each other: a module that is not yet
implemented, given no evidence this run, or that raises, is recorded in findings.json
with that status and never stops the rest of the pipeline.
"""

from __future__ import annotations

import argparse
import importlib
import sys
from pathlib import Path, PureWindowsPath

from core.config import TranceConfig
from core.custody_log import CustodyEntry, CustodyLog
from core.hashing import hash_file
from core.schema import ModuleResult
from findings import build_findings, write_findings
from report import write_report

MODULES = ("module_a_registry", "module_b_disk", "module_c_memory")
CUSTODY_FILENAME = "custody.json"


def run_module(name: str, config: TranceConfig, kwargs: dict) -> ModuleResult:
    """Import and run one module, converting every failure mode into a ModuleResult."""
    try:
        module = importlib.import_module(f"modules.{name}")
    except Exception as exc:  # a module may not even import on this platform (Windows-only APIs)
        return ModuleResult(module=name, status="error", message=f"import failed: {exc}")
    run = getattr(module, "run", None)
    if run is None:
        return ModuleResult(module=name, status="not_implemented", message="module defines no run()")
    try:
        return run(config, **kwargs)
    except Exception as exc:
        return ModuleResult(module=name, status="error", message=f"{type(exc).__name__}: {exc}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run the TRANCE pipeline end to end for one case.")
    parser.add_argument("--case", required=True, help="Case name; outputs go to <output-dir>/<case>/")
    parser.add_argument("--output-dir", type=Path, default=Path("output"), help="Default: %(default)s")
    parser.add_argument("--evidence-dir", type=Path, help="Recorded in findings.json for provenance")
    parser.add_argument("--verbose", action="store_true", help="Also print each module's full text summary")

    disk = parser.add_argument_group("module_b_disk")
    disk.add_argument(
        "--disk-profile", type=Path,
        help="Static extracted Tor Browser profile containing SQLite databases",
    )
    disk.add_argument("--tor-dir", type=Path, help="Static extracted TorBrowser/Data/Tor directory")
    disk.add_argument(
        "--disk-image", type=Path, help="Raw image to carve (optional and potentially slow)"
    )

    memory = parser.add_argument_group("module_c_memory")
    memory.add_argument("--dump", type=Path, help="Memory image to analyze: a dumper.py process dump (.bin) or a winpmem_acquire.py full-memory image (.raw)")
    memory.add_argument("--onion", help="Target .onion address to anchor URL matching to")
    memory.add_argument("--host", help="Target host[:port] to anchor URL matching to")
    memory.add_argument("--username", help="Known username to highlight in recovered search queries")
    memory.add_argument(
        "--source-type",
        choices=("process", "full-memory"),
        default="process",
        help="Which acquisition path produced --dump: dumper.py's live-process dump, or "
        "winpmem_acquire.py's full physical-memory image. Provenance/labeling only — this "
        "does not run either acquisition tool (both need a separate elevated Windows "
        "session); it only tells the analyzer which one already produced --dump (default: %(default)s)",
    )
    memory.add_argument(
        "--vol3-path",
        help="Path (or bare name, resolved on $PATH) to Volatility3's 'vol' entry point. "
        "When set, also runs the structural plugins (psscan/netscan/filescan/cmdline/"
        "hivelist) against --dump as a second, independent pass alongside string carving. "
        "Omit to skip Volatility3 entirely (default: skipped)",
    )
    memory.add_argument(
        "--vol3-extract-process",
        help="Process image name (e.g. firefox.exe) to isolate before string-carving: uses "
        "Volatility3 to find its PID (windows.pslist) and extract just its resident pages "
        "(windows.memmap --dump), then runs analyzer.py against that smaller extract instead "
        "of the whole image. Requires --vol3-path and --source-type full-memory; best-effort "
        "-- falls back to analyzing the full image if the process already exited by capture "
        "time or extraction otherwise fails. Omit to always analyze the full image (default)",
    )
    memory.add_argument(
        "--vol3-extract-pid",
        type=int,
        help="Skip --vol3-extract-process's PID discovery and extract this exact PID instead",
    )
    args = parser.parse_args(argv)

    if (
        args.case in (".", "..")
        or Path(args.case).name != args.case
        or PureWindowsPath(args.case).name != args.case
    ):
        parser.error("--case must be a single directory name without path separators")

    if args.dump and not (args.onion or args.host):
        print("[!] --dump given without --onion/--host: memory targeted-URL section will be empty", file=sys.stderr)

    output_dir = args.output_dir / args.case
    for evidence_root in (args.disk_profile, args.tor_dir):
        if evidence_root and output_dir.resolve().is_relative_to(evidence_root.resolve()):
            parser.error(f"case output directory must be outside disk evidence: {evidence_root}")
    existing_outputs = [output_dir / name for name in ("findings.json", "report.html", CUSTODY_FILENAME)]
    if any(path.exists() for path in existing_outputs):
        parser.error(f"case outputs already exist; choose a new --case: {output_dir}")
    config = TranceConfig(
        case_name=args.case, output_dir=output_dir, evidence_dir=args.evidence_dir, verbose=args.verbose
    )
    output_dir.mkdir(parents=True, exist_ok=True)

    module_kwargs: dict[str, dict] = {
        "module_b_disk": {
            "profile_dir": args.disk_profile,
            "tor_dir": args.tor_dir,
            "disk_image": args.disk_image,
        },
        "module_c_memory": {
            "dump": args.dump,
            "onion": args.onion,
            "host": args.host,
            "username": args.username,
            "source_type": args.source_type,
            "vol3_path": args.vol3_path,
            "vol3_extract_process": args.vol3_extract_process,
            "vol3_extract_pid": args.vol3_extract_pid,
        },
    }

    results: list[ModuleResult] = []
    for name in MODULES:
        result = run_module(name, config, module_kwargs.get(name, {}))
        results.append(result)
        suffix = f" — {result.message}" if result.message else ""
        print(f"[*] {name}: {result.status} ({len(result.artifacts)} artifacts){suffix}")

    findings = build_findings(config, results)
    findings_path = write_findings(findings, output_dir)
    report_path = write_report(findings, output_dir)

    custody = CustodyLog(output_dir / CUSTODY_FILENAME)
    disk_result = next((r for r in results if r.module == "module_b_disk"), None)
    if disk_result:
        for section in ("profile", "tor_daemon"):
            detail = disk_result.details.get(section, {})
            source = detail.get("evidence_dir") or detail.get("tor_data_dir")
            if not source:
                continue
            for relative, digest in detail.get("integrity", {}).get("source_sha256", {}).items():
                custody.record(
                    CustodyEntry(
                        artifact_path=str(Path(source) / relative),
                        sha256=digest,
                        action="verified_and_analyzed",
                        notes=f"module_b_disk {section}; disposable-copy analysis",
                    )
                )
        raw_carve = disk_result.details.get("raw_carve", {})
        if raw_carve.get("image_sha256"):
            custody.record(
                CustodyEntry(
                    artifact_path=raw_carve["image"],
                    sha256=raw_carve["image_sha256"],
                    action="hashed_and_carved",
                    notes="SHA-256 calculated during the sequential raw-byte scan",
                )
            )
    memory_result = next((r for r in results if r.module == "module_c_memory" and r.status == "ok"), None)
    if memory_result:
        dump = memory_result.details["dump"]
        custody.record(
            CustodyEntry(
                artifact_path=dump["path"],
                sha256=dump["sha256"],
                action="analyzed",
                notes=f"integrity_verified={dump['integrity_verified']}",
            )
        )
    for path in (findings_path, report_path):
        custody.record(CustodyEntry(artifact_path=str(path), sha256=hash_file(path), action="generated"))
    custody.save()

    if args.verbose and memory_result:
        from modules.module_c_memory.analyzer import format_summary

        print()
        print(format_summary(memory_result.details))

    print(f"\n[*] findings: {findings_path}")
    print(f"[*] report:   {report_path}")
    print(f"[*] custody:  {custody.log_path}")
    return 2 if any(r.status == "error" for r in results) else 0


if __name__ == "__main__":
    sys.exit(main())
