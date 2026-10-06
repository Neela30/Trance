"""Privileged helper: mount a disk image's Windows volume read-only for analysis.

The GUI runs this through pkexec (one password prompt) as

    mount_helper.py session <absolute image path>

It attaches the image read-only with qemu-nbd, mounts its largest NTFS partition with
ntfs-3g (-o ro,show_sys_files,streams_interface=windows -- what module_b_disk's
$MFT/$UsnJrnl/Zone.Identifier readers need), prints one JSON line per event on
stdout, then waits. Sending "unmount" on stdin -- or the GUI going away, which closes
stdin -- unmounts, detaches and removes the mountpoint. Cleanup therefore happens even
if the GUI crashes.

Runs as root, so: standard library only, no shell, argument lists only, fixed PATH,
read-only at every layer, and the image must be an existing regular file. Also usable
in a frozen build as `trance-gui --mount-helper session <image>`.
"""

from __future__ import annotations

import json
import os
import secrets
import signal
import stat
import subprocess
import sys
import time
from pathlib import Path

SAFE_PATH = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
MOUNT_BASE = Path("/run/trance-mounts")
NTFS_OPTIONS = "ro,show_sys_files,streams_interface=windows,allow_other"
NBD_MAX_PART = "16"
PARTITION_WAIT_SECONDS = 10

VDI_SIGNATURE = 0xBEDA107F
VDI_DIFFERENCING = 4
FORMAT_BY_SUFFIX = {
    ".vdi": "vdi",
    ".vmdk": "vmdk",
    ".qcow2": "qcow2",
    ".vhdx": "vhdx",
    ".vhd": "vpc",
}


class HelperError(Exception):
    pass


def emit(event: str, **fields: object) -> None:
    print(json.dumps({"event": event, **fields}), flush=True)


def detect_format(path: Path) -> str:
    """qemu-nbd's --format, from the image's own header. A VirtualBox *differencing*
    VDI (a snapshot) only holds changes against its parent, so mounting it alone shows
    garbage -- refused with the fix instead."""
    with path.open("rb") as fh:
        head = fh.read(512)
    if head[:4] == b"QFI\xfb":
        return "qcow2"
    if head[:8] == b"vhdxfile":
        return "vhdx"
    if head[:8] == b"conectix":
        return "vpc"
    if head[:4] == b"KDMV" or head.startswith(b"# Disk DescriptorFile"):
        return "vmdk"
    if len(head) >= 0x50 and int.from_bytes(head[0x40:0x44], "little") == VDI_SIGNATURE:
        if int.from_bytes(head[0x4C:0x50], "little") == VDI_DIFFERENCING:
            raise HelperError(
                "This .vdi is a VirtualBox snapshot (differencing image) and cannot be "
                "mounted on its own. Flatten it first: VBoxManage clonemedium disk "
                "<snapshot.vdi> <flat.vdi> --format VDI, then pick the flat copy."
            )
        return "vdi"
    return FORMAT_BY_SUFFIX.get(path.suffix.lower(), "raw")


def choose_partition(lsblk: dict) -> tuple[str, list[dict]]:
    """The largest NTFS partition (the Windows volume, not System Reserved or
    Recovery). Falls back to the device itself for an image of a single volume."""
    [device] = lsblk["blockdevices"]
    candidates = device.get("children") or [device]
    listed = [
        {
            "name": c["name"],
            "size": int(c.get("size") or 0),
            "fstype": c.get("fstype"),
            "label": c.get("label"),
        }
        for c in candidates
    ]
    ntfs = [c for c in listed if (c["fstype"] or "").lower() == "ntfs"]
    if not ntfs:
        raise HelperError(
            "No NTFS partition found in this image (partitions: "
            + ", ".join(f"{c['name']} {c['fstype'] or 'unknown'}" for c in listed)
            + ")."
        )
    return max(ntfs, key=lambda c: c["size"])["name"], listed


def free_nbd_device(sys_block: Path = Path("/sys/block")) -> str:
    """The first /dev/nbdN with nothing attached (size 0 and no serving pid)."""
    devices = sorted(
        (p for p in sys_block.glob("nbd*") if p.name[3:].isdigit()),
        key=lambda p: int(p.name[3:]),
    )
    for device in devices:
        size = (device / "size").read_text().strip() if (device / "size").exists() else "0"
        if size == "0" and not (device / "pid").exists():
            return device.name
    raise HelperError("No free /dev/nbd device (all in use).")


def _run(*args: str, check: bool = True) -> subprocess.CompletedProcess:
    result = subprocess.run(
        list(args), capture_output=True, text=True, env={"PATH": SAFE_PATH, "LC_ALL": "C"}
    )
    if check and result.returncode != 0:
        detail = (result.stderr or result.stdout).strip().splitlines()
        raise HelperError(f"{args[0]} failed: {detail[-1] if detail else result.returncode}")
    return result


def _ensure_nbd_module() -> None:
    if not Path("/sys/module/nbd").exists():
        _run("modprobe", "nbd", f"max_part={NBD_MAX_PART}")
        return
    max_part = Path("/sys/module/nbd/parameters/max_part")
    if max_part.exists() and max_part.read_text().strip() == "0":
        raise HelperError(
            "The nbd kernel module is loaded without partition support. Run "
            "'sudo modprobe -r nbd' (with no image attached) and try again."
        )


def _validated_image(argument: str) -> Path:
    path = Path(argument)
    if not path.is_absolute():
        raise HelperError("The image path must be absolute.")
    resolved = path.resolve(strict=True)
    if not stat.S_ISREG(resolved.stat().st_mode):
        raise HelperError(f"Not a regular file: {resolved}")
    return resolved


def _wait_for_partitions(device: str) -> dict:
    deadline = time.monotonic() + PARTITION_WAIT_SECONDS
    while True:
        _run("udevadm", "settle", check=False)
        listing = json.loads(
            _run("lsblk", "-J", "-b", "-o", "NAME,SIZE,FSTYPE,LABEL", f"/dev/{device}").stdout
        )
        has_fs = any(
            c.get("fstype") for c in listing["blockdevices"][0].get("children") or []
        ) or listing["blockdevices"][0].get("fstype")
        if has_fs or time.monotonic() > deadline:
            return listing
        time.sleep(0.5)


class Session:
    def __init__(self, image: Path):
        self.image = image
        self.device: str | None = None
        self.mountpoint: Path | None = None
        self.mounted = False

    def mount(self) -> None:
        image_format = detect_format(self.image)
        _ensure_nbd_module()
        self.device = free_nbd_device()
        _run(
            "qemu-nbd",
            "--read-only",
            f"--format={image_format}",
            f"--connect=/dev/{self.device}",
            str(self.image),
        )
        partition, partitions = choose_partition(_wait_for_partitions(self.device))
        MOUNT_BASE.mkdir(mode=0o755, exist_ok=True)
        self.mountpoint = MOUNT_BASE / f"{self.device}-{secrets.token_hex(4)}"
        self.mountpoint.mkdir(mode=0o755)
        _run("ntfs-3g", "-o", NTFS_OPTIONS, f"/dev/{partition}", str(self.mountpoint))
        self.mounted = True
        emit(
            "mounted",
            mountpoint=str(self.mountpoint),
            device=f"/dev/{self.device}",
            partition=f"/dev/{partition}",
            format=image_format,
            partitions=partitions,
        )

    def cleanup(self) -> None:
        problems = []
        if self.mounted and self.mountpoint:
            for _ in range(5):
                if _run("umount", str(self.mountpoint), check=False).returncode == 0:
                    break
                time.sleep(1)
            else:
                _run("umount", "-l", str(self.mountpoint), check=False)
                problems.append("volume was busy; detached lazily")
            self.mounted = False
        if self.device:
            _run("qemu-nbd", f"--disconnect=/dev/{self.device}", check=False)
            self.device = None
        if self.mountpoint and self.mountpoint.exists():
            try:
                self.mountpoint.rmdir()
            except OSError as exc:
                problems.append(f"mountpoint not removed: {exc}")
        emit("unmounted", problems=problems)


def _raise_exit(_signum, _frame) -> None:
    raise SystemExit(1)


def session(image_argument: str) -> int:
    os.umask(0o022)
    for signum in (signal.SIGTERM, signal.SIGHUP, signal.SIGINT):
        signal.signal(signum, _raise_exit)
    current = None
    try:
        current = Session(_validated_image(image_argument))
        current.mount()
        for line in sys.stdin:  # EOF (GUI gone) ends the loop just like "unmount"
            if line.strip() == "unmount":
                break
        return 0
    except (HelperError, OSError, ValueError) as exc:
        emit("error", message=str(exc))
        return 1
    finally:
        if current is not None:
            current.cleanup()


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    if len(args) != 2 or args[0] != "session":
        print("usage: mount_helper.py session <absolute image path>", file=sys.stderr)
        return 2
    if os.geteuid() != 0:
        emit("error", message="The mount helper must run as root (via pkexec).")
        return 1
    return session(args[1])


if __name__ == "__main__":
    sys.exit(main())
