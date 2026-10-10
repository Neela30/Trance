"""TRANCE folder-aware analyze entry point: point at an acquire_all.py evidence
folder and get the same findings.json/report.html/custody.json main.py produces.

    python analyze_evidence.py --case demo --evidence-dir evidence \\
        --onion <address>.onion --host 127.0.0.1:5000 --username alice

Thin wrapper, not a second pipeline: resolves each artifact's concrete path
(from --evidence-dir's acquire_manifest.json, written by acquire_all.py, or
by best-effort filename globbing if no manifest is present -- so a hand-built
evidence folder still works) and calls main.main() with the equivalent argv.
Any of main.py's own flags passed explicitly here always win over
auto-discovery, so this stays a convenience layer, not a second source of
truth for the pipeline itself.
"""

from __future__ import annotations

import argparse
import functools
import json
import multiprocessing
import sys
from pathlib import Path, PureWindowsPath

import main as main_module

# main.py's --source-type default; used when a manifest doesn't say otherwise.
_DEFAULT_SOURCE_TYPE = "process"
# modules/module_b_disk/acquire.py's DOWNLOADS_SCAN_FILENAME; not imported, so this
# wrapper doesn't pull the acquire side in.
DOWNLOADS_SCAN_FILENAME = "zone_identifier_scan.json"
# modules/module_b_disk/acquire_ntfs.py's MFT_FILENAME, per volume under disk/ntfs/<letter>/.
NTFS_MFT_FILENAME = "MFT"


def _latest(paths: list[Path]) -> Path | None:
    return max(paths, key=lambda p: p.stat().st_mtime) if paths else None


def _rebase_onto(evidence_dir: Path, recorded: str) -> str:
    """Map a manifest path onto wherever the evidence folder lives *now*.

    The manifest was written on the target, so a recorded path may be relative to the
    acquire-time working directory ("evidence\\registry\\SYSTEM_..."), absolute on the
    target ("C:\\forensics\\...\\evidence\\registry\\SYSTEM_..."), or already relative to
    the evidence folder ("registry/SYSTEM_..."), and use Windows separators either way.
    None of those resolve as-is once the folder is copied to the examiner's machine, so
    take the longest trailing run of components that exists under evidence_dir. If
    nothing exists, fall back to the full relative form so main.py reports a clear
    file-not-found against the evidence folder rather than some unrelated CWD.
    """
    parts = [p for p in PureWindowsPath(recorded).parts if p not in ("\\", "/")]
    parts = [p for p in parts if not PureWindowsPath(p).drive]
    for start in range(len(parts)):
        candidate = evidence_dir.joinpath(*parts[start:])
        if candidate.exists():
            return str(candidate)
    return str(evidence_dir.joinpath(*parts)) if parts else str(evidence_dir)


def _resolve_from_manifest(evidence_dir: Path, manifest: dict) -> dict:
    resolved: dict[str, str] = {}

    def ok_path(entry: object) -> str | None:
        # "None" is what trance-acquire builds before the dumper returned its path
        # wrote into the manifest for a successful live dump.
        if (
            isinstance(entry, dict)
            and entry.get("status") == "ok"
            and entry.get("path") not in (None, "", "None")
        ):
            return _rebase_onto(evidence_dir, entry["path"])
        return None

    registry = manifest.get("registry", {})
    for key, flag in (
        ("SYSTEM", "system"),
        ("NTUSER.DAT", "ntuser"),
        ("Amcache.hve", "amcache"),
        ("SOFTWARE", "software"),
        ("UsrClass.dat", "usrclass"),
    ):
        path = ok_path(registry.get(key))
        if path:
            resolved[flag] = path

    memory = manifest.get("memory", {})
    full_image = memory.get("full_image", {})
    live_dump = memory.get("live_dump", {})
    if path := ok_path(full_image):
        resolved["dump"] = path
        resolved["source_type"] = full_image.get("source_type", "full-memory")
    elif path := ok_path(live_dump):
        resolved["dump"] = path
        resolved["source_type"] = live_dump.get("source_type", _DEFAULT_SOURCE_TYPE)

    disk = manifest.get("disk", {})
    if path := ok_path(disk.get("profile")):
        resolved["disk_profile"] = path
    if path := ok_path(disk.get("tor_dir")):
        resolved["tor_dir"] = path
    if path := ok_path(disk.get("downloads")):
        resolved["downloads_scan"] = path
    if path := ok_path(disk.get("ntfs")):
        resolved["ntfs_dir"] = path

    # Fill gaps from this same folder's own files -- never from another acquisition:
    # a step the manifest says succeeded but recorded no usable path for (older
    # trance-acquire builds wrote "None" for the live dump), and the tor_dir/downloads
    # outputs older manifests don't list, or list as "error" after a partial copy.
    globbed = _resolve_by_globbing(evidence_dir)
    memory_ok = any(
        isinstance(e, dict) and e.get("status") == "ok" for e in (full_image, live_dump)
    )
    if "dump" not in resolved and memory_ok and "dump" in globbed:
        resolved["dump"] = globbed["dump"]
        resolved["source_type"] = globbed["source_type"]
    for key in ("tor_dir", "downloads_scan", "ntfs_dir"):
        if key not in resolved and key in globbed:
            resolved[key] = globbed[key]

    return resolved


def _resolve_by_globbing(evidence_dir: Path) -> dict:
    """acquire_all.py's registry/memory/disk subfolder layout is preferred; falls back
    to evidence_dir itself for a flat folder (e.g. registry/memory acquire scripts run
    directly and copied off a VM as-is, predating acquire_all.py, or hand-assembled) --
    same filename patterns, just not sorted into subfolders."""
    resolved: dict[str, str] = {}

    registry_dir = evidence_dir / "registry"
    if not registry_dir.is_dir():
        registry_dir = evidence_dir
    for pattern, flag in (
        ("SYSTEM_*", "system"),
        ("NTUSER_*.DAT", "ntuser"),
        ("Amcache_*.hve", "amcache"),
        ("SOFTWARE_*", "software"),
        ("UsrClass_*.dat", "usrclass"),
    ):
        match = _latest([p for p in registry_dir.glob(pattern) if p.suffix != ".sha256"])
        if match:
            resolved[flag] = str(match)

    memory_dir = evidence_dir / "memory"
    if not memory_dir.is_dir():
        memory_dir = evidence_dir
    full_image = _latest(list(memory_dir.glob("fullmem_*.raw")))
    live_dump = _latest(list(memory_dir.glob("firefox_*.bin")))
    if full_image:
        resolved["dump"] = str(full_image)
        resolved["source_type"] = "full-memory"
    elif live_dump:
        resolved["dump"] = str(live_dump)
        resolved["source_type"] = _DEFAULT_SOURCE_TYPE

    disk_profile = evidence_dir / "disk" / "profile"
    if disk_profile.is_dir():
        resolved["disk_profile"] = str(disk_profile)
    tor_dir = evidence_dir / "disk" / "tor_dir"
    if tor_dir.is_dir():
        resolved["tor_dir"] = str(tor_dir)
    downloads_scan = evidence_dir / "disk" / "downloads" / DOWNLOADS_SCAN_FILENAME
    if downloads_scan.is_file():
        resolved["downloads_scan"] = str(downloads_scan)
    ntfs_dir = evidence_dir / "disk" / "ntfs"
    if ntfs_dir.is_dir() and any(ntfs_dir.glob(f"*/{NTFS_MFT_FILENAME}")):
        resolved["ntfs_dir"] = str(ntfs_dir)

    return resolved


# Profiles every Windows install has that are not a person's account.
_NON_USER_PROFILES = frozenset({"default", "default user", "public", "all users"})


def _ci_child(folder: Path, name: str) -> Path | None:
    """`folder/name` matched case-insensitively. Windows paths are case-insensitive but a
    volume mounted with ntfs-3g is not ("Windows/appcompat/Programs" on a real disk)."""
    exact = folder / name
    if exact.exists():
        return exact
    try:
        for entry in folder.iterdir():
            if entry.name.casefold() == name.casefold():
                return entry
    except OSError:
        pass
    return None


def _ci_path(root: Path, *parts: str) -> Path | None:
    current: Path | None = root
    for part in parts:
        current = _ci_child(current, part) if current is not None else None
        if current is None:
            return None
    return current


def _ci_file(root: Path, *parts: str) -> str | None:
    found = _ci_path(root, *parts)
    return str(found) if found is not None and found.is_file() else None


@functools.lru_cache(maxsize=8)
def resolve_volume(root: str) -> dict:
    """Inputs found inside a mounted Windows volume, in resolve_evidence()'s shape (plus a
    "volume_notes" list saying what was chosen and why).

    A disk image (the powered-off case) holds the same evidence an acquisition folder does --
    registry hives, the Tor Browser profile and the tor data folder -- at their usual Windows
    locations; without this only Module B's whole-volume passes ever saw it. Tor Browser is
    found with the acquisition side's own search (the torrc signature; the most recently
    active install when there are several), and the user whose NTUSER.DAT / UsrClass.dat are
    used is the one that install lives under. Cached per path: the GUI asks on every form
    change, and a read-only mount does not change."""
    from core.exceptions import AcquisitionError
    from modules.module_b_disk.acquire import (
        discover_tor_browser_paths,
        find_tor_browser_installations,
        most_recently_active,
    )

    volume = Path(root)
    if not volume.is_dir():
        return {}
    found: dict = {"volume_notes": []}
    notes = found["volume_notes"]

    for key, parts in (
        ("system", ("Windows", "System32", "config", "SYSTEM")),
        ("software", ("Windows", "System32", "config", "SOFTWARE")),
        ("amcache", ("Windows", "AppCompat", "Programs", "Amcache.hve")),
    ):
        path = _ci_file(volume, *parts)
        if path:
            found[key] = path

    users_dir = _ci_path(volume, "Users")
    installs = find_tor_browser_installations([users_dir]) if users_dir else []
    if not installs:
        installs = find_tor_browser_installations([volume])
    install = None
    if installs:
        install = most_recently_active(installs)
        notes.append(f"Tor Browser found inside the volume at {install}")
        others = [str(p) for p in installs if p != install]
        if others:
            notes.append(
                "More Tor Browser installs on this volume, not analysed (the most recently "
                f"active one was used): {', '.join(others)}"
            )
        try:
            profile, tor_dir = discover_tor_browser_paths(install)
            found["disk_profile"] = str(profile)
            found["tor_dir"] = str(tor_dir)
        except AcquisitionError as exc:
            notes.append(f"Tor Browser profile / data folder not used: {exc}")

    user_dir = None
    if users_dir is not None:
        if install is not None:
            try:
                relative = install.resolve().relative_to(users_dir.resolve())
                user_dir = users_dir / relative.parts[0]
            except ValueError:
                pass
        if user_dir is None:
            people = sorted(
                d
                for d in users_dir.iterdir()
                if d.is_dir()
                and d.name.casefold() not in _NON_USER_PROFILES
                and _ci_file(d, "NTUSER.DAT")
            )
            if len(people) == 1:
                user_dir = people[0]
            elif people:
                notes.append(
                    "Several user profiles and none holds Tor Browser, so no NTUSER.DAT was "
                    f"chosen: {', '.join(p.name for p in people)}"
                )
    if user_dir is not None:
        ntuser = _ci_file(user_dir, "NTUSER.DAT")
        usrclass = _ci_file(user_dir, "AppData", "Local", "Microsoft", "Windows", "UsrClass.dat")
        if ntuser:
            found["ntuser"] = ntuser
        if usrclass:
            found["usrclass"] = usrclass
        notes.append(f"User hives from the profile {user_dir.name}")
    return found


def with_volume_inputs(resolved: dict, disk_root: str | Path | None) -> dict:
    """`resolved` (an evidence folder's inputs) with anything still missing filled in from a
    mounted volume. An acquired copy is the verified evidence, so it is never replaced by
    the live mount's file; the examiner's own overrides are applied after this, by callers."""
    merged = dict(resolved)
    if not disk_root:
        return merged
    volume = resolve_volume(str(disk_root))
    for key, value in volume.items():
        if key == "volume_notes":
            merged["volume_notes"] = list(value)
        elif not merged.get(key):
            merged[key] = value
    return merged


def resolve_evidence(evidence_dir: Path) -> dict:
    manifest_path = evidence_dir / "acquire_manifest.json"
    if manifest_path.is_file():
        manifest = json.loads(manifest_path.read_text())
        return _resolve_from_manifest(evidence_dir, manifest)
    return _resolve_by_globbing(evidence_dir)


def build_argv(args: argparse.Namespace, resolved: dict) -> list[str]:
    argv = ["--case", args.case, "--output-dir", str(args.output_dir)]
    if args.evidence_dir:
        argv += ["--evidence-dir", str(args.evidence_dir)]
    if args.verbose:
        argv.append("--verbose")
    if args.report_timezone:
        argv += ["--report-timezone", args.report_timezone]

    overrides = {
        "ntuser": args.ntuser,
        "system": args.system,
        "amcache": args.amcache,
        "software": args.software,
        "usrclass": args.usrclass,
        "disk_profile": args.disk_profile,
        "tor_dir": args.tor_dir,
        "downloads_scan": args.downloads_scan,
        "ntfs_dir": args.ntfs_dir,
        "dump": args.dump,
        "source_type": args.source_type,
    }
    flag_names = {
        "ntuser": "--ntuser",
        "system": "--system",
        "amcache": "--amcache",
        "software": "--software",
        "usrclass": "--usrclass",
        "disk_profile": "--disk-profile",
        "tor_dir": "--tor-dir",
        "downloads_scan": "--downloads-scan",
        "ntfs_dir": "--ntfs-dir",
        "dump": "--dump",
        "source_type": "--source-type",
    }
    for key, flag in flag_names.items():
        value = overrides[key] if overrides[key] is not None else resolved.get(key)
        if value:
            argv += [flag, str(value)]

    if args.disk_image:
        argv += ["--disk-image", str(args.disk_image)]
    if args.disk_root:
        argv += ["--disk-root", str(args.disk_root)]
    for flag, value in (
        ("--onion", args.onion),
        ("--host", args.host),
        ("--username", args.username),
        ("--vol3-path", args.vol3_path),
        ("--vol3-extract-process", args.vol3_extract_process),
    ):
        if value:
            argv += [flag, value]
    for name in getattr(args, "cookie_names", None) or []:
        argv += ["--cookie-name", name]
    if args.vol3_extract_pid is not None:
        argv += ["--vol3-extract-pid", str(args.vol3_extract_pid)]
    return argv


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Analyze an acquire_all.py evidence folder and produce the TRANCE case report."
    )
    parser.add_argument("--case", required=True, help="Case name; passed through to main.py")
    parser.add_argument("--output-dir", type=Path, default=Path("output"))
    parser.add_argument(
        "--evidence-dir",
        type=Path,
        help="acquire_all.py output folder (or any folder with the same registry/memory/disk "
        "layout); used both for auto-discovery and as findings.json provenance",
    )
    parser.add_argument("--verbose", action="store_true")
    parser.add_argument(
        "--report-timezone",
        help="IANA zone name (e.g. Asia/Colombo) for the report's local-time display; "
        "passed through to main.py. Omit to auto-detect this machine's own timezone",
    )

    parser.add_argument("--ntuser", type=Path, help="Override auto-discovery")
    parser.add_argument("--system", type=Path, help="Override auto-discovery")
    parser.add_argument("--amcache", type=Path, help="Override auto-discovery")
    parser.add_argument("--software", type=Path, help="Override auto-discovery")
    parser.add_argument("--usrclass", type=Path, help="Override auto-discovery")
    parser.add_argument("--disk-profile", type=Path, help="Override auto-discovery")
    parser.add_argument("--tor-dir", type=Path, help="Override auto-discovery")
    parser.add_argument("--disk-image", type=Path, help="Raw image to carve (not auto-discovered)")
    parser.add_argument(
        "--disk-root",
        type=Path,
        help="Root of a read-only mounted Windows volume for Zone.Identifier/NTFS-journal "
        "carving (not auto-discovered)",
    )
    parser.add_argument("--downloads-scan", type=Path, help="Override auto-discovery")
    parser.add_argument("--ntfs-dir", type=Path, help="Override auto-discovery")
    parser.add_argument("--dump", type=Path, help="Override auto-discovery")
    parser.add_argument("--source-type", choices=("process", "full-memory"), default=None)

    parser.add_argument("--onion")
    parser.add_argument("--host")
    parser.add_argument("--username")
    parser.add_argument("--cookie-name", action="append", dest="cookie_names")
    parser.add_argument("--vol3-path")
    parser.add_argument("--vol3-extract-process")
    parser.add_argument("--vol3-extract-pid", type=int)

    args = parser.parse_args(argv)

    resolved = resolve_evidence(args.evidence_dir) if args.evidence_dir else {}
    resolved = with_volume_inputs(resolved, args.disk_root)
    for note in resolved.get("volume_notes", []):
        print(f"[*] {note}", file=sys.stderr)
    main_argv = build_argv(args, resolved)
    return main_module.main(main_argv)


if __name__ == "__main__":
    # A frozen Windows exe re-launches itself for every worker process of the memory
    # scan's pool; without this each worker would start the whole app again.
    multiprocessing.freeze_support()
    sys.exit(main())
