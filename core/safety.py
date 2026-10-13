"""Examiner-side safety guards for analysis: never parse untrusted evidence as root, and
optionally cap how much memory/CPU the analysis process may use.

The evidence comes off a machine that may be compromised. TRANCE's parsers (regipy, sqlite,
the NTFS and memory carvers) all run on attacker-influenced bytes; a parser bug exploited as
root owns the examiner's laptop, as an ordinary user it is contained to that account. The
resource limits keep a crafted file (a decompression bomb, a pathological hive) from taking
the whole machine down. Stdlib only.
"""

from __future__ import annotations

import os
import sys

from core.exceptions import TranceError

# GUI analysis child defaults (Linux only). 0 means "no limit". Overridable per run from the
# GUI, or with these environment variables.
DEFAULT_MEMORY_LIMIT_MB = 16 * 1024
DEFAULT_CPU_LIMIT_SECONDS = 4 * 60 * 60
MEMORY_LIMIT_ENV = "TRANCE_LIMIT_MEMORY_MB"
CPU_LIMIT_ENV = "TRANCE_LIMIT_CPU_SECONDS"


class UnsafeEnvironmentError(TranceError):
    """Raised when analysis is asked to run in an environment TRANCE refuses (as root)."""


def running_as_root() -> bool:
    geteuid = getattr(os, "geteuid", None)
    return bool(geteuid) and geteuid() == 0


def refuse_root(what: str = "analysis") -> None:
    if running_as_root():
        raise UnsafeEnvironmentError(
            f"Refusing to run {what} as root. Evidence from a possibly compromised machine is "
            "parsed here; run TRANCE as an ordinary user (the disk-image mount asks for "
            "administrator rights separately, only for the mount itself)."
        )


def limits_supported() -> bool:
    return sys.platform.startswith("linux")


def default_limits() -> tuple[int, int]:
    """(memory MB, CPU seconds) from the environment, else the built-in defaults."""
    return (
        _env_int(MEMORY_LIMIT_ENV, DEFAULT_MEMORY_LIMIT_MB),
        _env_int(CPU_LIMIT_ENV, DEFAULT_CPU_LIMIT_SECONDS),
    )


def _env_int(name: str, default: int) -> int:
    try:
        value = int(os.environ.get(name, "").strip())
    except ValueError:
        return default
    return max(0, value)


def apply_resource_limits(memory_mb: int | None, cpu_seconds: int | None) -> list[str]:
    """Lower this process's RLIMIT_AS / RLIMIT_CPU (inherited by every child it starts, e.g.
    the memory scan's worker pool and Volatility3). Linux only; elsewhere a no-op. Never
    raises a limit above what is already in force. Returns one note per limit, for the log.
    """
    if not limits_supported():
        return ["resource limits are only applied on Linux; none set"]
    import resource

    notes = []
    for label, which, value, unit, scale in (
        ("memory (address space)", resource.RLIMIT_AS, memory_mb, "MB", 1024 * 1024),
        ("CPU time", resource.RLIMIT_CPU, cpu_seconds, "s", 1),
    ):
        if not value:
            notes.append(f"{label}: no limit")
            continue
        wanted = int(value) * scale
        _soft, hard = resource.getrlimit(which)
        if hard != resource.RLIM_INFINITY and hard < wanted:
            wanted = hard
        try:
            resource.setrlimit(which, (wanted, wanted))
        except (ValueError, OSError) as exc:
            notes.append(f"{label}: could not set limit ({exc})")
            continue
        notes.append(f"{label}: limited to {wanted // scale} {unit}")
    return notes
