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
from pathlib import Path

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

    memory = parser.add_argument_group("module_c_memory")
    memory.add_argument("--dump", type=Path, help="firefox.exe memory dump (.bin) from dumper.py")
    memory.add_argument("--onion", help="Target .onion address to anchor URL matching to")
    memory.add_argument("--host", help="Target host[:port] to anchor URL matching to")
    memory.add_argument("--username", help="Known username to highlight in recovered search queries")
    args = parser.parse_args(argv)

    if args.dump and not (args.onion or args.host):
        print("[!] --dump given without --onion/--host: memory targeted-URL section will be empty", file=sys.stderr)

    output_dir = args.output_dir / args.case
    config = TranceConfig(
        case_name=args.case, output_dir=output_dir, evidence_dir=args.evidence_dir, verbose=args.verbose
    )
    output_dir.mkdir(parents=True, exist_ok=True)

    module_kwargs: dict[str, dict] = {
        "module_c_memory": {
            "dump": args.dump,
            "onion": args.onion,
            "host": args.host,
            "username": args.username,
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
