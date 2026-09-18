"""Registry hive acquisition for Module A (Windows only, admin-required).

Exports the three hives modules/module_a_registry/pipeline.py analyzes --
NTUSER.DAT, SYSTEM, Amcache.hve -- from a live Windows target to captures/,
mirroring module_c_memory's acquire-then-analyze split (dumper.py /
winpmem_acquire.py): acquisition needs a live, elevated Windows session;
analysis (pipeline.py) runs anywhere, offline, against the exported copies.

Windows locks these hives while running, so a plain file copy fails ("file
in use" / "access denied"). Two different export mechanisms, both built
into Windows -- nothing examiner-supplied to install, unlike
winpmem_acquire.py's WinPMEM:

  - NTUSER.DAT / SYSTEM are *loaded* registry hives (HKCU / HKLM\\SYSTEM):
    `reg save` asks the OS itself for a consistent snapshot. Only reaches
    hives actually loaded into the live registry tree right now -- HKCU is
    always the CURRENT session's user; a different, currently-logged-in
    user's hive isn't reachable this way (see --ntuser-user below).
  - Amcache.hve is *not* a loaded registry key at all (no HKLM/HKCU path
    for it) -- it's a standalone locked file at
    C:\\Windows\\AppCompat\\Programs\\Amcache.hve. `reg save` can't touch
    it. Uses a Volume Shadow Copy instead: snapshot the volume, copy the
    file out of the point-in-time-consistent snapshot (the live lock
    doesn't apply there), then delete the shadow copy immediately after --
    minimal footprint, nothing left behind on the target.

--ntuser-user reuses the same VSS mechanism for a NAMED user's NTUSER.DAT
instead of the live HKCU export -- covers both "a different user is
logged in right now" (their hive is locked too, just not reachable via
your own HKCU) and "that user isn't logged in at all" (unlocked on disk,
but VSS works either way, so this is one code path instead of two).
"""

from __future__ import annotations

import argparse
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Callable

from core.custody_log import CustodyEntry, CustodyLog
from core.exceptions import AcquisitionError
from core.hashing import hash_file

if sys.platform == "win32":
    import ctypes

    def _is_admin() -> bool:
        try:
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            return False

else:

    def _is_admin() -> bool:
        return False


ACQUIRE_TIMEOUT_SECONDS = 300
_SHADOW_VOLUME_RE = re.compile(r"Shadow Copy Volume Name:\s*(\S+)")
_SHADOW_ID_RE = re.compile(r"Shadow Copy ID:\s*(\{[0-9A-Fa-f-]+\})")


def _run(cmd: list[str], timeout: int = ACQUIRE_TIMEOUT_SECONDS) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except FileNotFoundError as exc:
        raise AcquisitionError(f"Required Windows command not found: {cmd[0]} ({exc})") from exc
    except subprocess.TimeoutExpired as exc:
        raise AcquisitionError(f"{cmd[0]} timed out after {timeout}s: {exc}") from exc


def _timestamp() -> str:
    return time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())


def _hash_sidecar_custody(path: Path, custody: CustodyLog, notes: str) -> str:
    digest = hash_file(path)
    path.with_name(path.name + ".sha256").write_text(f"{digest}  {path.name}\n")
    custody.record(CustodyEntry(artifact_path=str(path), sha256=digest, action="acquire", notes=notes))
    return digest


def _reg_save(hive_key: str, output_path: Path) -> None:
    """`reg save <hive_key> <output_path>` -- exports a currently-loaded hive."""
    result = _run(["reg", "save", hive_key, str(output_path)])
    if result.returncode != 0:
        raise AcquisitionError(
            f"'reg save {hive_key}' failed (exit {result.returncode}).\n"
            f"--- stdout ---\n{result.stdout}\n--- stderr ---\n{result.stderr}"
        )
    if not output_path.exists() or output_path.stat().st_size == 0:
        raise AcquisitionError(
            f"'reg save {hive_key}' reported success but produced no (or an empty) {output_path.name}."
        )


def acquire_system(output_dir: Path, custody: CustodyLog) -> Path:
    output_path = output_dir / f"SYSTEM_{_timestamp()}"
    _reg_save("HKLM\\SYSTEM", output_path)
    _hash_sidecar_custody(output_path, custody, "SYSTEM hive via reg save HKLM\\SYSTEM")
    return output_path


def acquire_ntuser_live(output_dir: Path, custody: CustodyLog) -> Path:
    """The CURRENT session's user (HKCU) -- reg save, no VSS needed."""
    output_path = output_dir / f"NTUSER_{_timestamp()}.DAT"
    _reg_save("HKCU", output_path)
    _hash_sidecar_custody(output_path, custody, "NTUSER.DAT (current session) via reg save HKCU")
    return output_path


def _create_shadow_copy(drive: str = "C:") -> tuple[str, str]:
    """Returns (shadow_id, shadow_volume_path). Caller must _delete_shadow_copy() when done."""
    result = _run(["vssadmin", "create", "shadow", f"/for={drive}"])
    if result.returncode != 0:
        raise AcquisitionError(
            f"vssadmin could not create a shadow copy of {drive} (exit {result.returncode}).\n"
            f"--- stdout ---\n{result.stdout}\n--- stderr ---\n{result.stderr}\n"
            "Common cause: Volume Shadow Copy Service not running, or a Windows edition/policy "
            "that restricts vssadmin -- try `net start vss` first, or confirm you're elevated."
        )
    volume_match = _SHADOW_VOLUME_RE.search(result.stdout)
    id_match = _SHADOW_ID_RE.search(result.stdout)
    if not volume_match or not id_match:
        raise AcquisitionError(
            "vssadmin reported success but its output didn't contain a recognizable shadow "
            f"copy volume/ID -- output shape may differ on this Windows version:\n{result.stdout}"
        )
    return id_match.group(1), volume_match.group(1)


def _delete_shadow_copy(shadow_id: str) -> None:
    """Best-effort cleanup, never raises -- so a copy failure still gets reported as
    itself rather than being masked by a cleanup error, and cleanup still runs either way."""
    result = _run(["vssadmin", "delete", "shadows", f"/shadow={shadow_id}", "/quiet"])
    if result.returncode != 0:
        print(
            f"[!] Warning: could not delete shadow copy {shadow_id} automatically "
            f"(exit {result.returncode}) -- remove it manually: "
            f"vssadmin delete shadows /shadow={shadow_id}",
            file=sys.stderr,
        )


def _copy_via_shadow(relative_path: str, output_path: Path, drive: str = "C:") -> None:
    """Copy `relative_path` (e.g. r"Windows\\AppCompat\\Programs\\Amcache.hve") off a
    fresh VSS snapshot of `drive`, bypassing the live file lock, then remove the
    snapshot -- minimal footprint, nothing left resident on the target afterward.

    The \\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopyN\\... path vssadmin prints is a
    standard Win32 extended/device path; shutil.copyfile() (ordinary file I/O) can read
    it directly, no special VSS API needed.
    """
    shadow_id, shadow_volume = _create_shadow_copy(drive)
    try:
        source = f"{shadow_volume}\\{relative_path}"
        try:
            shutil.copyfile(source, output_path)
        except OSError as exc:
            raise AcquisitionError(f"Could not copy {relative_path!r} from shadow copy {shadow_id}: {exc}") from exc
        if not output_path.exists() or output_path.stat().st_size == 0:
            raise AcquisitionError(
                f"Copy from shadow copy {shadow_id} reported success but produced no "
                f"(or an empty) {output_path.name}."
            )
    finally:
        _delete_shadow_copy(shadow_id)


def acquire_amcache(output_dir: Path, custody: CustodyLog) -> Path:
    output_path = output_dir / f"Amcache_{_timestamp()}.hve"
    _copy_via_shadow(r"Windows\AppCompat\Programs\Amcache.hve", output_path)
    _hash_sidecar_custody(output_path, custody, "Amcache.hve via Volume Shadow Copy")
    return output_path


def acquire_ntuser_for_user(user: str, output_dir: Path, custody: CustodyLog) -> Path:
    """A NAMED user's NTUSER.DAT via VSS -- works whether or not that user is the
    current session (reg save HKCU only ever reaches your own live session)."""
    output_path = output_dir / f"NTUSER_{user}_{_timestamp()}.DAT"
    _copy_via_shadow(rf"Users\{user}\NTUSER.DAT", output_path)
    _hash_sidecar_custody(output_path, custody, f"NTUSER.DAT for user {user!r} via Volume Shadow Copy")
    return output_path


def acquire_all(
    output_dir: Path,
    include_system: bool = True,
    include_ntuser: bool = True,
    include_amcache: bool = True,
    ntuser_user: str | None = None,
) -> dict:
    """Best-effort: each hive is attempted independently -- one failing (e.g. Amcache's
    VSS step, if the service is disabled) doesn't stop the others, same isolation
    philosophy as volatility_analyze.py's per-plugin handling."""
    if sys.platform != "win32":
        raise AcquisitionError("Registry hive acquisition only runs on Windows.")
    if not _is_admin():
        raise AcquisitionError("Not running elevated. Re-run as Administrator -- SYSTEM and Amcache both need it.")

    output_dir.mkdir(parents=True, exist_ok=True)
    custody = CustodyLog(output_dir / f"registry_acquire_{_timestamp()}.custody.json")
    results: dict[str, dict] = {}

    def attempt(name: str, fn: Callable[[], Path]) -> None:
        try:
            path = fn()
            results[name] = {"status": "ok", "path": str(path), "message": None}
            print(f"[*] {name}: {path}")
        except AcquisitionError as exc:
            results[name] = {"status": "error", "path": None, "message": str(exc)}
            print(f"[!] {name} failed: {exc}", file=sys.stderr)

    if include_system:
        attempt("SYSTEM", lambda: acquire_system(output_dir, custody))
    if include_ntuser:
        if ntuser_user:
            attempt("NTUSER.DAT", lambda: acquire_ntuser_for_user(ntuser_user, output_dir, custody))
        else:
            attempt("NTUSER.DAT", lambda: acquire_ntuser_live(output_dir, custody))
    if include_amcache:
        attempt("Amcache.hve", lambda: acquire_amcache(output_dir, custody))

    custody.save()
    results["custody_log_path"] = str(custody.log_path)
    return results


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Export NTUSER.DAT, SYSTEM and Amcache.hve from a live Windows target for Module A."
    )
    parser.add_argument("--output-dir", type=Path, default=Path("captures"), help="Default: %(default)s")
    parser.add_argument("--skip-system", action="store_true", help="Don't export SYSTEM")
    parser.add_argument("--skip-ntuser", action="store_true", help="Don't export NTUSER.DAT")
    parser.add_argument("--skip-amcache", action="store_true", help="Don't export Amcache.hve")
    parser.add_argument(
        "--ntuser-user",
        help="Export this named user's NTUSER.DAT via Volume Shadow Copy instead of the current "
        "session's HKCU (needed if Tor Browser ran under a different Windows account than the "
        "one running this script)",
    )
    args = parser.parse_args()

    try:
        results = acquire_all(
            args.output_dir,
            include_system=not args.skip_system,
            include_ntuser=not args.skip_ntuser,
            include_amcache=not args.skip_amcache,
            ntuser_user=args.ntuser_user,
        )
    except AcquisitionError as exc:
        print(f"[!] {exc}", file=sys.stderr)
        sys.exit(1)

    failed = [k for k, v in results.items() if isinstance(v, dict) and v.get("status") == "error"]
    print(f"\n[*] Custody log: {results['custody_log_path']}")
    if failed:
        print(f"[!] {len(failed)} hive(s) failed: {', '.join(failed)}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
