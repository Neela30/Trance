"""Full physical-memory acquisition via an examiner-supplied WinPMEM binary (Windows only).

Complements dumper.py: dumper.py only captures a *live* firefox.exe's readable committed
memory, so it produces nothing once the process has exited. WinPMEM images the whole
physical address space instead, so freed/unmapped pages from an already-exited process
can still be present and recoverable by analyzer.py's existing string carver -- the image
is just bytes, no process-specific structure needed on the way in.

WinPMEM itself is not vendored or downloaded here -- point --winpmem-path at an
examiner-supplied binary (https://github.com/Velocidex/WinPmem releases), same
"external tool, not a Python dependency" pattern used for RawCopy/TScopy in the
pagefile/hiberfil design (see context.md). No new third-party Python dependency is
introduced: acquisition is a subprocess call plus the stdlib.
"""

from __future__ import annotations

import argparse
import subprocess
import sys
import time
from pathlib import Path

from core.custody_log import CustodyEntry, CustodyLog
from core.exceptions import AcquisitionError
from core.hashing import hash_file
from core.winadmin import is_admin as _is_admin

# A full physical-RAM image can legitimately take a long time on a large-memory
# machine; bounded rather than unbounded so a hung driver/process doesn't block forever.
ACQUIRE_TIMEOUT_SECONDS = 3600


def run_winpmem(
    winpmem_path: Path, output_path: Path, extra_args: list[str] | None = None
) -> subprocess.CompletedProcess[str]:
    """Shell out to the WinPMEM binary.

    Common (4.x) WinPMEM releases take the output path as a trailing positional argument
    (``winpmem.exe <outfile>``). Older builds/forks use different flags (e.g. ``-o
    <outfile>``) -- pass --winpmem-arg to add whatever a specific binary needs rather than
    this module guessing one fixed CLI shape for a tool it doesn't vendor.
    """
    cmd = [str(winpmem_path), *(extra_args or []), str(output_path)]
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=ACQUIRE_TIMEOUT_SECONDS)
    except FileNotFoundError as exc:
        raise AcquisitionError(
            f"WinPMEM binary not found or not executable: {winpmem_path} ({exc})"
        ) from exc
    except OSError as exc:
        raise AcquisitionError(f"Failed to launch WinPMEM at {winpmem_path}: {exc}") from exc
    except subprocess.TimeoutExpired as exc:
        raise AcquisitionError(
            f"WinPMEM did not finish within {ACQUIRE_TIMEOUT_SECONDS}s: {exc}"
        ) from exc


def acquire(winpmem_path: Path, output_dir: Path, extra_args: list[str] | None = None) -> Path:
    """Run WinPMEM to capture a full physical-memory image; hash, sidecar and log it.

    Returns the path to the acquired .raw image on success; raises AcquisitionError on
    any failure (missing binary, not elevated, WinPMEM's own non-zero exit, or an
    empty/missing output file despite a zero exit code).
    """
    if sys.platform != "win32":
        raise AcquisitionError("WinPMEM acquisition only runs on Windows.")
    if not winpmem_path.is_file():
        raise AcquisitionError(f"WinPMEM binary not found: {winpmem_path}")
    if not _is_admin():
        raise AcquisitionError(
            "Not running elevated. Re-run as Administrator -- WinPMEM needs its kernel driver loaded."
        )

    output_dir.mkdir(parents=True, exist_ok=True)
    timestamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    image_path = output_dir / f"fullmem_{timestamp}.raw"

    print(f"[*] Running WinPMEM: {winpmem_path} -> {image_path}")
    result = run_winpmem(winpmem_path, image_path, extra_args)
    if result.returncode != 0:
        image_path.unlink(missing_ok=True)
        raise AcquisitionError(
            f"WinPMEM exited with code {result.returncode}.\n"
            f"--- stdout ---\n{result.stdout}\n--- stderr ---\n{result.stderr}"
        )
    if not image_path.exists() or image_path.stat().st_size == 0:
        image_path.unlink(missing_ok=True)
        raise AcquisitionError(
            "WinPMEM reported success (exit 0) but produced no output file, or an empty one."
        )

    total_bytes = image_path.stat().st_size
    digest = hash_file(image_path)
    hash_path = image_path.with_name(image_path.name + ".sha256")
    hash_path.write_text(f"{digest}  {image_path.name}\n")

    custody = CustodyLog(output_dir / f"{image_path.stem}.custody.json")
    custody.record(
        CustodyEntry(
            artifact_path=str(image_path),
            sha256=digest,
            action="acquire",
            notes=f"full-memory image via WinPMEM ({winpmem_path.name}), source_type=full-memory, "
            f"{total_bytes} bytes",
        )
    )
    custody.save()

    print(f"[*] Image:       {image_path}")
    print(f"[*] Bytes:       {total_bytes} ({total_bytes / (1024 * 1024):.1f} MB)")
    print(f"[*] SHA-256:     {digest}")
    print(f"[*] Hash file:   {hash_path}")
    print(f"[*] Custody log: {custody.log_path}")
    return image_path


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Acquire a full physical-memory image via an examiner-supplied WinPMEM binary."
    )
    parser.add_argument(
        "--winpmem-path", type=Path, required=True, help="Path to the WinPMEM executable"
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("captures"),
        help="Directory for the .raw image, .sha256 sidecar and custody log (default: %(default)s)",
    )
    parser.add_argument(
        "--winpmem-arg",
        dest="winpmem_args",
        action="append",
        default=[],
        help="Extra flag to pass through to WinPMEM before the output path; repeatable "
        "(e.g. --winpmem-arg -o for a build that needs -o <outfile> instead of a bare positional path)",
    )
    args = parser.parse_args()
    try:
        acquire(args.winpmem_path, args.output_dir, args.winpmem_args)
    except AcquisitionError as exc:
        print(f"[!] {exc}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
