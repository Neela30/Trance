"""Live acquisition of the largest firefox.exe process's readable committed memory (Windows only)."""

from __future__ import annotations

import argparse
import ctypes
import sys
import time
from pathlib import Path
from typing import Iterator

import psutil

from core.custody_log import CustodyEntry, CustodyLog
from core.exceptions import AcquisitionError
from core.hashing import hash_file

if sys.platform == "win32":
    from ctypes import wintypes

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

    PROCESS_QUERY_INFORMATION = 0x0400
    PROCESS_VM_READ = 0x0010

    MEM_COMMIT = 0x1000
    PAGE_GUARD = 0x100
    READABLE_PROTECT = {0x02, 0x04, 0x08, 0x20, 0x40, 0x80}  # READONLY, READWRITE, WRITECOPY, EXEC_READ, EXEC_READWRITE, EXEC_WRITECOPY

    class MEMORY_BASIC_INFORMATION(ctypes.Structure):
        _fields_ = [
            ("BaseAddress", ctypes.c_void_p),
            ("AllocationBase", ctypes.c_void_p),
            ("AllocationProtect", wintypes.DWORD),
            ("RegionSize", ctypes.c_size_t),
            ("State", wintypes.DWORD),
            ("Protect", wintypes.DWORD),
            ("Type", wintypes.DWORD),
        ]

    kernel32.OpenProcess.restype = wintypes.HANDLE
    kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    kernel32.VirtualQueryEx.restype = ctypes.c_size_t
    kernel32.VirtualQueryEx.argtypes = [
        wintypes.HANDLE,
        ctypes.c_void_p,
        ctypes.POINTER(MEMORY_BASIC_INFORMATION),
        ctypes.c_size_t,
    ]
    kernel32.ReadProcessMemory.restype = wintypes.BOOL
    kernel32.ReadProcessMemory.argtypes = [
        wintypes.HANDLE,
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_size_t,
        ctypes.POINTER(ctypes.c_size_t),
    ]
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]

MAX_USERSPACE_ADDRESS = 0x7FFFFFFFFFFF
MAX_REGION_READ = 512 * 1024 * 1024  # safety cap per region


def find_largest_firefox() -> psutil.Process:
    best: psutil.Process | None = None
    best_rss = -1
    for proc in psutil.process_iter(["pid", "name"]):
        try:
            if (proc.info["name"] or "").lower() != "firefox.exe":
                continue
            rss = proc.memory_info().rss
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
        if rss > best_rss:
            best_rss = rss
            best = proc
    if best is None:
        raise AcquisitionError("No firefox.exe process found. Is Tor Browser running?")
    return best


def iter_readable_regions(handle: int) -> Iterator[tuple[int, int]]:
    address = 0
    mbi = MEMORY_BASIC_INFORMATION()
    mbi_size = ctypes.sizeof(mbi)
    while address < MAX_USERSPACE_ADDRESS:
        result = kernel32.VirtualQueryEx(handle, ctypes.c_void_p(address), ctypes.byref(mbi), mbi_size)
        if result == 0:
            break
        region_size = mbi.RegionSize or mbi_size
        base_protect = mbi.Protect & 0xFF
        if mbi.State == MEM_COMMIT and base_protect in READABLE_PROTECT and not (mbi.Protect & PAGE_GUARD):
            yield (mbi.BaseAddress or address), region_size
        address += region_size


def dump_process_memory(pid: int, output_path: Path) -> tuple[int, int]:
    handle = kernel32.OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, pid)
    if not handle:
        raise AcquisitionError(
            f"OpenProcess failed for PID {pid} (error {ctypes.get_last_error()}). Run as Administrator."
        )
    region_count = 0
    total_bytes = 0
    try:
        with open(output_path, "wb") as out:
            for base_address, region_size in iter_readable_regions(handle):
                read_size = min(region_size, MAX_REGION_READ)
                buffer = (ctypes.c_char * read_size)()
                bytes_read = ctypes.c_size_t(0)
                ok = kernel32.ReadProcessMemory(
                    handle, ctypes.c_void_p(base_address), buffer, read_size, ctypes.byref(bytes_read)
                )
                if not ok or bytes_read.value == 0:
                    continue
                out.write(buffer.raw[: bytes_read.value])
                region_count += 1
                total_bytes += bytes_read.value
    finally:
        kernel32.CloseHandle(handle)
    return region_count, total_bytes


def acquire(output_dir: Path) -> None:
    if sys.platform != "win32":
        raise AcquisitionError("The memory dumper only runs on Windows.")

    proc = find_largest_firefox()
    pid = proc.pid
    rss_mb = proc.memory_info().rss / (1024 * 1024)
    print(f"[*] Selected firefox.exe PID {pid} (RSS {rss_mb:.1f} MB)")

    output_dir.mkdir(parents=True, exist_ok=True)
    timestamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    dump_path = output_dir / f"firefox_{pid}_{timestamp}.bin"

    region_count, total_bytes = dump_process_memory(pid, dump_path)
    if region_count == 0:
        dump_path.unlink(missing_ok=True)
        raise AcquisitionError("No readable regions captured. Re-run elevated (Administrator).")

    digest = hash_file(dump_path)
    hash_path = dump_path.with_name(dump_path.name + ".sha256")
    hash_path.write_text(f"{digest}  {dump_path.name}\n")

    custody = CustodyLog(output_dir / f"{dump_path.stem}.custody.json")
    custody.record(
        CustodyEntry(
            artifact_path=str(dump_path),
            sha256=digest,
            action="acquire",
            notes=f"firefox.exe PID {pid}, {region_count} regions, {total_bytes} bytes",
        )
    )
    custody.save()

    print(f"[*] PID:            {pid}")
    print(f"[*] Regions dumped: {region_count}")
    print(f"[*] Bytes dumped:   {total_bytes} ({total_bytes / (1024 * 1024):.1f} MB)")
    print(f"[*] SHA-256:        {digest}")
    print(f"[*] Dump:           {dump_path}")
    print(f"[*] Hash file:      {hash_path}")
    print(f"[*] Custody log:    {custody.log_path}")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Dump the largest firefox.exe process's readable committed memory to a .bin file."
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("captures"),
        help="Directory for the .bin dump, .sha256 sidecar and custody log (default: %(default)s)",
    )
    args = parser.parse_args()
    try:
        acquire(args.output_dir)
    except AcquisitionError as exc:
        print(f"[!] {exc}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
