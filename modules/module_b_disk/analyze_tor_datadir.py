"""Analyze the Tor daemon's data directory from an acquired disk image.

This targets `TorBrowser/Data/Tor/`, which is NOT the Firefox profile and is
NOT covered by Tor Browser's permanent-private-browsing policy. The daemon
must persist this state across restarts to function, so unlike places.sqlite
it retains evidence of real network activity:

  state                       entry guards actually used, circuit counts,
                              time since last user interaction
  cached-microdesc-consensus  authority-signed consensus (valid-after gives a
                              network-anchored timestamp, independent of the
                              local clock)
  cached-microdescs[.new]     relay descriptors downloaded from the network
  onion-auth/*.auth_private   client-auth credentials naming a specific
                              hidden service in plaintext
  torrc                       ClientOnionAuthDir / DataDirectory config
  lock                        daemon start time

Timestamps are reported in UTC. NTFS stores mtimes in UTC, but Tor writes
VM-local time into the `state` header, so the two differ by the guest's
timezone offset -- which this script derives and reports explicitly, since a
large offset can shift the apparent *date* of an artifact.

Usage:
    python analyze_tor_datadir.py <path/to/Data/Tor> [--out report.json]
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from core.custody_log import CustodyEntry, CustodyLog
from core.hashing import hash_file
from modules.module_b_disk.evidence import working_copy

GUARD_RE = re.compile(r"^Guard\s+(.*)$", re.MULTILINE)
STATE_HEADER_RE = re.compile(
    r"^# Tor state file last generated on (\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) local time",
    re.MULTILINE,
)
CRED_RE = re.compile(
    r"^([a-z2-7]{56}):descriptor:x25519:([A-Za-z2-7]{52})", re.IGNORECASE | re.MULTILINE
)


def _utc(path: Path, metadata: dict | None = None) -> str:
    if metadata and metadata.get("modified_utc"):
        return metadata["modified_utc"]
    return dt.datetime.fromtimestamp(path.stat().st_mtime, dt.timezone.utc).isoformat()


def _load_filesystem_metadata(directory: Path) -> dict:
    path = directory / "filesystem_metadata.json"
    if not path.exists():
        return {"files": {}}
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data.get("files"), dict):
        raise ValueError("filesystem_metadata.json must contain a files object")
    return data


def _kv(text: str, key: str) -> str | None:
    m = re.search(rf"^{re.escape(key)}\s+(.+)$", text, re.MULTILINE)
    return m.group(1).strip() if m else None


def parse_state(path: Path) -> dict:
    """Parse tor's state file: guards, circuit stats, user-activity marker."""
    if not path.exists():
        return {"error": "not found"}
    text = path.read_text(errors="replace")

    guards = []
    for raw in GUARD_RE.findall(text):
        fields = dict(tok.split("=", 1) for tok in raw.split() if "=" in tok)
        # A guard tor actually routed traffic through carries confirmed_on and
        # non-zero pb_use_attempts; merely "sampled" guards were never used.
        used = float(fields.get("pb_use_attempts", 0) or 0) > 0
        guards.append(
            {
                "nickname": fields.get("nickname"),
                "rsa_id": fields.get("rsa_id"),
                "sampled_on": fields.get("sampled_on"),
                "confirmed_on": fields.get("confirmed_on"),
                "circuit_attempts": fields.get("pb_circ_attempts"),
                "circuit_successes": fields.get("pb_circ_successes"),
                "use_attempts": fields.get("pb_use_attempts"),
                "use_successes": fields.get("pb_use_successes"),
                "actually_used": used,
            }
        )

    # TotalBuildTimes counts binned builds plus abandoned (timed-out) ones, which
    # tor records only as CircuitBuildAbandonedCount; a mismatch after adding
    # those back means the file was truncated or tampered with.
    bins = [
        (int(a), int(b))
        for a, b in re.findall(r"^CircuitBuildTimeBin (\d+) (\d+)$", text, re.MULTILINE)
    ]
    hist_total = sum(n for _, n in bins)
    abandoned = int(_kv(text, "CircuitBuildAbandonedCount") or 0)
    total_builds = _kv(text, "TotalBuildTimes")

    last_written = _kv(text, "LastWritten")
    m = STATE_HEADER_RE.search(text)
    local_generated = m.group(1) if m else None

    tz_offset_hours = None
    if last_written and local_generated:
        try:
            utc = dt.datetime.fromisoformat(last_written)
            loc = dt.datetime.fromisoformat(local_generated)
            tz_offset_hours = round((loc - utc).total_seconds() / 3600, 2)
        except ValueError:
            pass

    mins_idle = _kv(text, "MinutesSinceUserActivity")

    return {
        "tor_version": _kv(text, "TorVersion"),
        "last_written_utc": last_written,
        "generated_guest_local": local_generated,
        "guest_utc_offset_hours": tz_offset_hours,
        "dormant": _kv(text, "Dormant"),
        "minutes_since_user_activity": mins_idle,
        "total_circuits_built": total_builds,
        "build_time_histogram_total": hist_total,
        "circuits_abandoned": abandoned,
        "histogram_consistent": (
            str(hist_total + abandoned) == total_builds if total_builds else None
        ),
        "build_time_ms_range": [bins[0][0], bins[-1][0]] if bins else None,
        "guards_sampled": len(guards),
        "guards_used": [g for g in guards if g["actually_used"]],
        "guards_all": guards,
    }


def parse_consensus(path: Path, metadata: dict | None = None) -> dict:
    """Pull the authority-signed validity window off the cached consensus."""
    if not path.exists():
        return {"error": "not found"}
    with path.open("rb") as fh:
        head = fh.read(2048).decode("utf-8", errors="replace")
    return {
        "file_mtime_utc": _utc(path, metadata),
        "size_bytes": path.stat().st_size,
        "network_status_version": _kv(head, "network-status-version"),
        "valid_after_utc": _kv(head, "valid-after"),
        "fresh_until_utc": _kv(head, "fresh-until"),
        "valid_until_utc": _kv(head, "valid-until"),
    }


def parse_onion_auth(auth_dir: Path, metadata: dict | None = None) -> dict:
    """Read client-auth credentials; each names one hidden service."""
    if not auth_dir.is_dir():
        return {"error": "not found"}
    creds, ignored = [], []
    for f in sorted(auth_dir.iterdir()):
        if not f.is_file():
            continue
        st = f.stat()
        text = f.read_text(errors="replace")
        m = CRED_RE.search(text)
        file_metadata = (metadata or {}).get(f"onion-auth/{f.name}", {})
        entry = {
            "filename": f.name,
            "inode": file_metadata.get("inode", st.st_ino),
            "size": st.st_size,
            "mtime_utc": _utc(f, file_metadata),
            "sha256": hash_file(f),
            "onion_address": (m.group(1) + ".onion") if m else None,
            "x25519_private_key": m.group(2) if m else None,
        }
        # tor only loads files ending exactly in ".auth_private"; anything else
        # in this directory was placed by a user and was never read by tor.
        if f.name.endswith(".auth_private"):
            entry["recognized_filename"] = True
            creds.append(entry)
        else:
            entry["recognized_filename"] = False
            entry["note"] = "wrong extension - tor ignores this file"
            ignored.append(entry)
    return {"credentials": creds, "ignored_files": ignored}


def _parse_tor_directory(directory: Path, source: Path) -> dict:
    """Parse one disposable Tor data-directory copy."""
    filesystem_metadata = _load_filesystem_metadata(directory)
    files = filesystem_metadata["files"]
    torrc = directory / "torrc"
    return {
        "tor_data_dir": str(source),
        "state": parse_state(directory / "state"),
        "consensus": parse_consensus(
            directory / "cached-microdesc-consensus", files.get("cached-microdesc-consensus")
        ),
        "onion_auth": parse_onion_auth(directory / "onion-auth", files),
        "daemon_start_utc": (
            _utc(directory / "lock", files.get("lock")) if (directory / "lock").exists() else None
        ),
        "file_mtimes_utc": {
            f.name: _utc(f, files.get(f.name))
            for f in sorted(directory.iterdir())
            if f.is_file() and f.name not in ("hashes.sha256", "filesystem_metadata.json")
        },
        "torrc": torrc.read_text(errors="replace") if torrc.exists() else None,
        "filesystem_metadata": filesystem_metadata,
    }


def analyze_tor_directory(tor_dir: Path) -> dict:
    """Verify, copy, and analyze a static Tor data-directory acquisition."""
    source = tor_dir.resolve(strict=True)
    with working_copy(source) as (copy, hashes, verification):
        report = _parse_tor_directory(copy, source)
        report["hash_verification"] = verification
        report["integrity"] = {
            "manifest_status": "verified" if verification else "absent",
            "unmanifested_files": sorted(set(hashes) - set(verification) - {"hashes.sha256"}),
            "source_sha256": hashes,
            "source_unchanged": False,
        }
    report["integrity"]["source_unchanged"] = True
    report["analysis_status"] = (
        "incomplete" if report["state"].get("error") or report["consensus"].get("error") else "ok"
    )
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("tor_dir", type=Path, help="Path to TorBrowser/Data/Tor")
    parser.add_argument("--out", type=Path, default=None)
    parser.add_argument("--custody-log", type=Path, default=None)
    args = parser.parse_args()

    d: Path = args.tor_dir
    if not d.is_dir():
        print(f"error: {d} is not a directory", file=sys.stderr)
        return 1

    report = analyze_tor_directory(d)

    st = report["state"]
    print("=== TRANCE Module B - Tor daemon data directory ===\n")
    print(f"tor version        : {st.get('tor_version')}")
    print(f"daemon start (UTC) : {report['daemon_start_utc']}")
    print(f"state written (UTC): {st.get('last_written_utc')}")
    off = st.get("guest_utc_offset_hours")
    if off is not None:
        print(
            f"guest TZ offset    : UTC{off:+g}  " f"(guest local {st.get('generated_guest_local')})"
        )
        if abs(off) >= 6:
            print(
                "  !! large offset: guest-local artifact names (e.g. bookmark "
                "backups) may\n     show a different DATE than host-rendered "
                "mtimes for the same event."
            )

    print("\n-- network activity --")
    c = report["consensus"]
    if not c.get("error"):
        print(f"consensus valid-after (authority-signed): {c['valid_after_utc']}")
        print(f"consensus cached at (UTC)               : {c['file_mtime_utc']}")
        print(f"consensus size                          : {c['size_bytes']:,} bytes")
    print(
        f"circuits built     : {st.get('total_circuits_built')} "
        f"(histogram sums to {st.get('build_time_histogram_total')}, "
        f"consistent={st.get('histogram_consistent')})"
    )
    rng = st.get("build_time_ms_range")
    if rng:
        print(f"build times        : {rng[0]}-{rng[1]} ms")
    print(f"dormant            : {st.get('dormant')}")
    print(f"mins since user activity: {st.get('minutes_since_user_activity')}")

    used = st.get("guards_used", [])
    print(
        f"\n-- entry guards ({st.get('guards_sampled')} sampled, "
        f"{len(used)} actually carried traffic) --"
    )
    for g in used:
        print(f"  {g['nickname']:20s} {g['rsa_id']}")
        print(
            f"    confirmed {g['confirmed_on']}  circuits "
            f"{g['circuit_successes']}/{g['circuit_attempts']}  streams "
            f"{g['use_successes']}/{g['use_attempts']}"
        )

    oa = report["onion_auth"]
    print("\n-- client-auth credentials --")
    for c_ in oa.get("credentials", []):
        print(f"  {c_['filename']}")
        print(f"    hidden service : {c_['onion_address']}")
        print(f"    written  (UTC) : {c_['mtime_utc']}   inode {c_['inode']}")
    for c_ in oa.get("ignored_files", []):
        print(f"  {c_['filename']}  [{c_['note']}]")
        print(f"    written  (UTC) : {c_['mtime_utc']}   inode {c_['inode']}")

    print("\nCONCLUSION:")
    if st.get("guards_used"):
        print(
            "  Tor connected to the live network through the named entry guard(s) "
            "above.\n  Guard fingerprints, circuit counts and the authority-signed "
            "consensus are\n  written by tor itself and are independent of anything "
            "the browser records."
        )
    if st.get("minutes_since_user_activity") is not None:
        print(
            f"  A user interacted with Tor Browser within "
            f"{st['minutes_since_user_activity']} minute(s) of the state file\n"
            f"  being written -- an on-disk record of live activity, not mere "
            f"configuration."
        )
    if oa.get("credentials"):
        print(
            "  Client-auth credential(s) name specific hidden service(s) in "
            "plaintext.\n  Check inode/timestamp provenance before asserting these "
            "were written by tor\n  rather than placed by hand."
        )
    print("  Per-page browsing history remains unrecoverable from disk by design.")

    if args.custody_log:
        log = CustodyLog(args.custody_log)
        for name in ("state", "cached-microdesc-consensus", "torrc"):
            f = d / name
            if f.exists():
                log.record(
                    CustodyEntry(
                        artifact_path=str(f),
                        sha256=hash_file(f),
                        action="analyzed",
                        notes="analyze_tor_datadir.py Tor daemon state analysis",
                    )
                )
        log.save()

    if args.out:
        args.out.write_text(json.dumps(report, indent=2, default=str))
        print(f"\nJSON report written to {args.out}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
