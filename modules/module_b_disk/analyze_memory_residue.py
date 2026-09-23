"""Carve Windows' on-disk memory residue for Tor artifacts.

Tor Browser keeps visited addresses, page content and the tor daemon's
hidden-service descriptor cache in memory only, so a public onion service
leaves nothing in the profile or in Data/Tor. The one disk route to that
memory is the operating system writing RAM out on its own:

  pagefile.sys / swapfile.sys       paged-out process memory
  hiberfil.sys                      the whole RAM image at hibernation
  Windows/MEMORY.DMP, Minidump/     kernel crash dumps
  Users/*/AppData/Local/CrashDumps  per-process crash dumps (WER)

These are ordinary files on the mounted volume, so they are found by name and
carved with carve_onion_strings.scan. hiberfil.sys is Xpress-compressed on
Windows 8+, so plain carving only reaches its uncompressed header pages and any
slack: hits there are a lower bound and the file is flagged for a Volatility3
(windows.hibernation layer) or hibr2bin pass.

Usage:
    python analyze_memory_residue.py <mounted_volume_root> [--out report.json]
"""

from __future__ import annotations

import argparse
import datetime as dt
import glob
import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from modules.module_b_disk.carve_onion_strings import scan
from modules.module_b_disk.onion import is_v3_onion

CANDIDATES = (
    ("pagefile", "pagefile.sys"),
    ("swapfile", "swapfile.sys"),
    ("hibernation", "hiberfil.sys"),
    ("kernel_dump", "Windows/MEMORY.DMP"),
    ("minidump", "Windows/Minidump/*.dmp"),
    ("process_dump", "Users/*/AppData/Local/CrashDumps/*.dmp"),
    ("livekernel_dump", "Windows/LiveKernelReports/*.dmp"),
)


def _mtime_utc(path: Path) -> str:
    return dt.datetime.fromtimestamp(path.stat().st_mtime, dt.timezone.utc).isoformat()


def find_residue_files(root: Path) -> list[dict]:
    found = []
    for kind, pattern in CANDIDATES:
        for match in sorted(glob.glob(os.path.join(root, pattern))):
            path = Path(match)
            if path.is_symlink() or not path.is_file():
                continue
            found.append({"kind": kind, "path": str(path.relative_to(root))})
    return found


def carve_residue(root: Path) -> dict:
    root = root.resolve(strict=True)
    files = []
    for entry in find_residue_files(root):
        path = root / entry["path"]
        record = {
            **entry,
            "size": path.stat().st_size,
            "modified_utc": _mtime_utc(path),
            "compressed": entry["kind"] == "hibernation",
        }
        try:
            result = scan(path, [])
        except OSError as exc:
            record["error"] = f"{type(exc).__name__}: {exc}"
            files.append(record)
            continue
        record.update(
            {
                "sha256": result["image_sha256"],
                "onion_addresses": result["onion_addresses"],
                "client_auth_credentials": result["client_auth_credentials"],
                "utf16_filenames": result["utf16_filenames"],
                "tor_markers": result["tor_markers"],
            }
        )
        files.append(record)
    addresses: dict[str, dict] = {}
    for record in files:
        for address, hit in record.get("onion_addresses", {}).items():
            if not is_v3_onion(address):
                continue
            entry = addresses.setdefault(address, {"occurrences": 0, "files": []})
            entry["occurrences"] += hit["occurrences"]
            entry["files"].append(record["path"])
        for name in record.get("utf16_filenames", {}):
            address = name.split(".")[0]
            if is_v3_onion(address):
                entry = addresses.setdefault(address + ".onion", {"occurrences": 0, "files": []})
                entry["occurrences"] += record["utf16_filenames"][name]["occurrences"]
                if record["path"] not in entry["files"]:
                    entry["files"].append(record["path"])
    return {
        "volume_root": str(root),
        "files": files,
        "onion_addresses": addresses,
        "hibernation_present": any(f["kind"] == "hibernation" for f in files),
        "note": (
            "Memory residue is written by Windows, not Tor Browser: a hit proves the string "
            "was in RAM at some point, not when or which process held it. hiberfil.sys is "
            "compressed; carve results there are a lower bound."
        ),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root", type=Path, help="Root of the read-only mounted NTFS volume")
    parser.add_argument("--out", type=Path, help="Write the JSON report here")
    args = parser.parse_args(argv)
    try:
        report = carve_residue(args.root)
    except (OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        with args.out.open("x", encoding="utf-8") as stream:
            json.dump(report, stream, indent=2)
    print("=== TRANCE Module B — Memory residue on disk ===")
    if not report["files"]:
        print("no pagefile/swapfile/hiberfil/crash dumps on this volume")
    for record in report["files"]:
        status = record.get("error") or (
            f"{len(record['onion_addresses'])} onion address(es), "
            f"{len(record['client_auth_credentials'])} credential(s)"
        )
        flag = "  [compressed: lower bound]" if record["compressed"] else ""
        print(f"  {record['path']} ({record['size']:,} bytes): {status}{flag}")
    for address, hit in report["onion_addresses"].items():
        print(f"    {address}  x{hit['occurrences']}  in {', '.join(hit['files'])}")
    if args.out:
        print(f"Report: {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
