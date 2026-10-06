"""Registry hive acquisition for Module A (Windows only, admin-required).

Exports the hives modules/module_a_registry/pipeline.py analyzes --
NTUSER.DAT, SYSTEM, Amcache.hve, SOFTWARE, and (acquired but not yet parsed
as of Phase 0 of the Module A roadmap -- see pipeline.py's
_usrclass_extractors()) UsrClass.dat -- from a live Windows target to
captures/, mirroring module_c_memory's acquire-then-analyze split (dumper.py
/ winpmem_acquire.py): acquisition needs a live, elevated Windows session;
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
    minimal footprint, nothing left behind on the target. Shadow creation
    goes through WMI (Win32_ShadowCopy.Create() via PowerShell), not
    `vssadmin create shadow` -- confirmed on a real client-Windows target
    that vssadmin's own "create shadow" verb is Server-only ("Error:
    Invalid command", and its own printed command list omits it while
    still listing "Delete Shadows"/"List Shadows" as supported -- so
    deletion/cleanup still goes through vssadmin, only creation doesn't).

--ntuser-user reuses the same VSS mechanism for a NAMED user's NTUSER.DAT
instead of the live HKCU export -- covers both "a different user is
logged in right now" (their hive is locked too, just not reachable via
your own HKCU) and "that user isn't logged in at all" (unlocked on disk,
but VSS works either way, so this is one code path instead of two).
UsrClass.dat is always acquired via this same VSS path (see
acquire_usrclass()'s own docstring for why it has no "live" reg-save
variant the way NTUSER does) for the same target user --ntuser-user names,
or the current session's user if that wasn't given.
"""

from __future__ import annotations

import argparse
import os
import re
import shutil
import subprocess
import sys
import time
from collections.abc import Callable
from pathlib import Path

from core.custody_log import CustodyEntry, CustodyLog
from core.exceptions import AcquisitionError
from core.hashing import hash_file
from core.winadmin import is_admin as _is_admin

ACQUIRE_TIMEOUT_SECONDS = 300
_SHADOW_ID_LINE_RE = re.compile(r"^ShadowID=(\S+)", re.MULTILINE)
_DEVICE_OBJECT_LINE_RE = re.compile(r"^DeviceObject=(\S+)", re.MULTILINE)
# vssadmin's own "create shadow" verb is Server-only -- confirmed on a real client-Windows
# target: it returns "Error: Invalid command" and its own printed command list omits
# "Create Shadow" while still listing "Delete Shadows"/"List Shadows" as supported (so
# _delete_shadow_copy() below keeps using vssadmin; only creation needs a different path).
# WMI's Win32_ShadowCopy.Create() is the documented client-Windows workaround.
_CREATE_SHADOW_PS_SCRIPT = (
    "$ErrorActionPreference = 'Stop'; "
    "$result = (Get-WmiObject -List Win32_ShadowCopy).Create('{drive}\\', 'ClientAccessible'); "
    "if ($result.ReturnValue -ne 0) {{ "
    'Write-Error "Win32_ShadowCopy.Create failed, ReturnValue=$($result.ReturnValue)"; exit 1 }} '
    "$shadow = Get-WmiObject Win32_ShadowCopy | Where-Object {{ $_.ID -eq $result.ShadowID }}; "
    'Write-Output "ShadowID=$($shadow.ID)"; '
    'Write-Output "DeviceObject=$($shadow.DeviceObject)"'
)


def _run(
    cmd: list[str], timeout: int = ACQUIRE_TIMEOUT_SECONDS
) -> subprocess.CompletedProcess[str]:
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
    custody.record(
        CustodyEntry(artifact_path=str(path), sha256=digest, action="acquire", notes=notes)
    )
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


def acquire_software(output_dir: Path, custody: CustodyLog) -> Path:
    """SOFTWARE is a loaded hive (HKLM\\SOFTWARE), same as SYSTEM -- reg save gives a
    consistent snapshot directly, no VSS needed. Feeds ProfileList (SID -> username)
    and the Installed Programs (Uninstall key) artifact type."""
    output_path = output_dir / f"SOFTWARE_{_timestamp()}"
    _reg_save("HKLM\\SOFTWARE", output_path)
    _hash_sidecar_custody(output_path, custody, "SOFTWARE hive via reg save HKLM\\SOFTWARE")
    return output_path


def acquire_ntuser_live(output_dir: Path, custody: CustodyLog) -> Path:
    """The CURRENT session's user (HKCU) -- reg save, no VSS needed."""
    output_path = output_dir / f"NTUSER_{_timestamp()}.DAT"
    _reg_save("HKCU", output_path)
    _hash_sidecar_custody(output_path, custody, "NTUSER.DAT (current session) via reg save HKCU")
    return output_path


def _create_shadow_copy(drive: str = "C:") -> tuple[str, str]:
    """Returns (shadow_id, shadow_volume_path). Caller must _delete_shadow_copy() when done.

    Via WMI/PowerShell, not vssadmin -- see module-level note above _CREATE_SHADOW_PS_SCRIPT.
    """
    script = _CREATE_SHADOW_PS_SCRIPT.format(drive=drive.rstrip("\\"))
    result = _run(["powershell", "-NoProfile", "-NonInteractive", "-Command", script])
    if result.returncode != 0:
        raise AcquisitionError(
            f"Could not create a shadow copy of {drive} via WMI (exit {result.returncode}).\n"
            f"--- stdout ---\n{result.stdout}\n--- stderr ---\n{result.stderr}"
        )
    id_match = _SHADOW_ID_LINE_RE.search(result.stdout)
    device_match = _DEVICE_OBJECT_LINE_RE.search(result.stdout)
    if not id_match or not device_match:
        raise AcquisitionError(
            "Shadow copy creation reported success but its output didn't contain a "
            f"recognizable ShadowID/DeviceObject:\n{result.stdout}"
        )
    return id_match.group(1), device_match.group(1)


def _delete_shadow_copy(shadow_id: str) -> None:
    """Best-effort cleanup, never raises -- so a copy failure still gets reported as
    itself rather than being masked by a cleanup error, and cleanup still runs either way.
    vssadmin delete IS supported on client Windows (unlike create -- see above), confirmed
    by the same real target's own printed command list."""
    shadow_id = shadow_id if shadow_id.startswith("{") else f"{{{shadow_id}}}"
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
            raise AcquisitionError(
                f"Could not copy {relative_path!r} from shadow copy {shadow_id}: {exc}"
            ) from exc
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
    _hash_sidecar_custody(
        output_path, custody, f"NTUSER.DAT for user {user!r} via Volume Shadow Copy"
    )
    return output_path


def acquire_usrclass(user: str, output_dir: Path, custody: CustodyLog) -> Path:
    """UsrClass.dat for a named user, via VSS -- same pattern as
    acquire_ntuser_for_user(), and for the same reason: works whether or not that user is
    the current session. Deliberately always VSS (no "live" reg-save variant the way
    NTUSER has one) -- `reg save HKCU\\Software\\Classes` would reach the current
    session's live-mounted equivalent, but whether that produces a hive byte-structurally
    equivalent enough for regipy's ShellBags plugin (Phase 1) to run against is untested;
    a plain file copy of the real UsrClass.dat is unambiguously correct either way.

    Holds Shell Bags (folder-browsing history), among other things -- analysis of this
    hive is Phase 1 of the Module A roadmap; acquisition only is wired up for now.
    """
    output_path = output_dir / f"UsrClass_{user}_{_timestamp()}.dat"
    _copy_via_shadow(rf"Users\{user}\AppData\Local\Microsoft\Windows\UsrClass.dat", output_path)
    _hash_sidecar_custody(
        output_path, custody, f"UsrClass.dat for user {user!r} via Volume Shadow Copy"
    )
    return output_path


def _resolve_target_user(ntuser_user: str | None) -> str:
    """The user UsrClass.dat is acquired for is the same one NTUSER.DAT targets --
    "the target user" is one concept, not two separate flags. Falls back to the current
    session's own PROFILE FOLDER NAME (the literal directory under C:\\Users\\ --
    _copy_via_shadow() builds a filesystem path from this, not a registry lookup) when
    --ntuser-user wasn't given, i.e. "the user running this script".

    This is deliberately NOT the account's login/display name (os.getlogin(), USERNAME,
    getpass.getuser() -- all equivalent to each other, all login-name-based). Windows
    never renames an existing profile folder when an account's login name changes later
    (via Microsoft-account linking, `net user` rename, etc.), so the two can permanently
    diverge for a long-lived account -- confirmed in the field: a real run had the
    current login name as "Neela" while that same account's profile folder was (and had
    always been) C:\\Users\\Admin. `reg save HKCU` (acquire_ntuser_live(), no path
    involved -- it reads the live registry via the security token directly) correctly
    captured that session's real history either way, but this function's first two
    attempts (os.getlogin(), then USERNAME) both returned the login name "Neela" and
    sent the VSS copy looking for a nonexistent Users\\Neela\\... path, failing with "No
    such file or directory" -- a login name is simply the wrong kind of value for a
    filesystem path here, regardless of which login-name source is asked.

    USERPROFILE is Windows' own environment variable for "my current profile folder's
    full path" and is immune to this divergence -- tried first, its leaf directory name
    is exactly what's needed. Login-name-based resolution remains only as a fallback for
    a non-Windows dev/test machine, where USERPROFILE doesn't exist at all.
    """
    if ntuser_user:
        return ntuser_user
    userprofile = os.environ.get("USERPROFILE")
    if userprofile:
        name = Path(userprofile).name
        if name:
            return name
    try:
        username = os.getlogin()
    except OSError:
        username = None
    if not username:
        username = os.environ.get("USERNAME") or os.environ.get("USER")
    if not username:
        import getpass

        try:
            username = getpass.getuser()
        except OSError:
            username = None
    if not username:
        raise AcquisitionError(
            "Could not resolve the current username -- pass --ntuser-user explicitly."
        )
    return username


def acquire_all(
    output_dir: Path,
    include_system: bool = True,
    include_ntuser: bool = True,
    include_amcache: bool = True,
    include_software: bool = True,
    include_usrclass: bool = True,
    ntuser_user: str | None = None,
) -> dict:
    """Best-effort: each hive is attempted independently -- one failing (e.g. Amcache's
    VSS step, if the service is disabled) doesn't stop the others, same isolation
    philosophy as volatility_analyze.py's per-plugin handling."""
    if sys.platform != "win32":
        raise AcquisitionError("Registry hive acquisition only runs on Windows.")
    if not _is_admin():
        raise AcquisitionError(
            "Not running elevated. Re-run as Administrator -- SYSTEM and Amcache both need it."
        )

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
    if include_software:
        attempt("SOFTWARE", lambda: acquire_software(output_dir, custody))
    if include_usrclass:
        attempt(
            "UsrClass.dat",
            lambda: acquire_usrclass(_resolve_target_user(ntuser_user), output_dir, custody),
        )

    custody.save()
    results["custody_log_path"] = str(custody.log_path)
    return results


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Export NTUSER.DAT, SYSTEM, Amcache.hve, SOFTWARE and UsrClass.dat "
        "from a live Windows target for Module A."
    )
    parser.add_argument(
        "--output-dir", type=Path, default=Path("captures"), help="Default: %(default)s"
    )
    parser.add_argument("--skip-system", action="store_true", help="Don't export SYSTEM")
    parser.add_argument("--skip-ntuser", action="store_true", help="Don't export NTUSER.DAT")
    parser.add_argument("--skip-amcache", action="store_true", help="Don't export Amcache.hve")
    parser.add_argument("--skip-software", action="store_true", help="Don't export SOFTWARE")
    parser.add_argument("--skip-usrclass", action="store_true", help="Don't export UsrClass.dat")
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
            include_software=not args.skip_software,
            include_usrclass=not args.skip_usrclass,
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
