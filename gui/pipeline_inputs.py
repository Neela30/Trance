"""Pure logic for turning an analyze_evidence.resolve_evidence() result + GUI form
fields into main.run_pipeline()'s module_kwargs shape. No Qt import, so it's testable
without a PySide6 install -- same separation analyze_evidence.py already uses for
resolve_evidence()/build_argv()."""

from __future__ import annotations

from pathlib import Path


def module_kwargs_from_resolved(resolved: dict, onion: str, host: str, username: str) -> dict:
    """Same shape main.py's argparse builds -- see main.py's module_kwargs dict -- just
    sourced from analyze_evidence.resolve_evidence()'s output plus the GUI's targeting
    fields, instead of parsed CLI flags."""

    def _path(key: str) -> Path | None:
        value = resolved.get(key)
        return Path(value) if value else None

    return {
        "module_a_registry": {
            "ntuser": _path("ntuser"),
            "system": _path("system"),
            "amcache": _path("amcache"),
        },
        "module_b_disk": {
            "profile_dir": _path("disk_profile"),
            "tor_dir": _path("tor_dir"),
            "disk_image": None,
            "disk_root": None,
        },
        "module_c_memory": {
            "dump": _path("dump"),
            "onion": onion or None,
            "host": host or None,
            "username": username or None,
            "source_type": resolved.get("source_type", "process"),
            "vol3_path": None,
            "vol3_extract_process": None,
            "vol3_extract_pid": None,
        },
    }
