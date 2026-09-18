"""Raw byte-level carve for Tor artifacts across an entire disk image.

Unlike recover_evidence.py, which parses live files inside a mounted
filesystem, this scans the image as an undifferentiated byte stream. That
means it also reaches unallocated space, file slack, MFT-resident data and
deleted-but-not-yet-overwritten blocks -- the places a .onion address can
survive after every file that held it is gone.

Reads in overlapping chunks so a match spanning a chunk boundary is not
missed, and reports the byte offset of every hit so findings can be tied
back to a physical location in the image.

Usage:
    python carve_onion_strings.py <image_or_device> [--out hits.json]
                                  [--extra-pattern REGEX]
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from core.custody_log import CustodyEntry, CustodyLog

CHUNK = 64 * 1024 * 1024
# Longest thing we search for is a v3 onion host plus a little context, so an
# overlap of a few hundred bytes is comfortably enough to catch a straddler.
OVERLAP = 512

# v3 onion addresses are 56 base32 chars; v2 (long dead, but cheap to catch)
# were 16. Case-insensitive because the string may have been stored uppercase.
ONION_RE = re.compile(rb"[a-z2-7]{16}(?:[a-z2-7]{40})?\.onion", re.IGNORECASE)

# Tor's client-authorisation credential files identify the hidden service by
# its bare 56-char address with NO ".onion" suffix, so ONION_RE never sees it:
#   <address>:descriptor:x25519:<base32 private key>
# These are the highest-value disk artifacts for attributing access to a
# specific hidden service, so they get their own pattern.
AUTH_CRED_RE = re.compile(rb"([a-z2-7]{56}):descriptor:x25519:([A-Za-z2-7]{52})", re.IGNORECASE)

# Same address stored as a UTF-16LE filename (e.g. "<addr>.auth_private" as it
# appears in an NTFS MFT record or directory index) -- letters interleaved with
# NUL bytes, which no ASCII pattern will match.
UTF16_ONION_RE = re.compile(
    rb"(?:[a-z2-7]\x00){16}(?:(?:[a-z2-7]\x00){40})?(?:\.\x00o\x00n\x00i\x00o\x00n\x00"
    rb"|\.\x00a\x00u\x00t\x00h\x00_\x00p\x00r\x00i\x00v\x00a\x00t\x00e\x00)",
    re.IGNORECASE,
)

# Strings that indicate Tor was present/running even when no address survives.
MARKER_PATTERNS = {
    "tor_control": rb"NEWNYM|SIGNAL NEWNYM",
    "tor_state": rb"EntryGuard[A-Za-z]*",
    "tor_consensus": rb"network-status-version 3",
    "tor_browser_path": rb"[Tt]or ?[Bb]rowser[\\/](?:Browser|Data)",
    "torrc": rb"HiddenServiceDir|ClientOnionAuthDir|SocksPort",
    "onion_auth": rb"descriptor:x25519:",
}
MARKER_RE = {k: re.compile(v) for k, v in MARKER_PATTERNS.items()}


def scan(image: Path, extra: list[re.Pattern]) -> dict:
    size = image.stat().st_size
    onion_hits: dict[bytes, list[int]] = {}
    onion_counts: Counter[bytes] = Counter()
    auth_creds: dict[tuple[bytes, bytes], list[int]] = {}
    auth_counts: Counter[tuple[bytes, bytes]] = Counter()
    utf16_hits: dict[bytes, list[int]] = {}
    utf16_counts: Counter[bytes] = Counter()
    marker_hits: dict[str, list[int]] = {k: [] for k in MARKER_RE}
    marker_counts: Counter[str] = Counter()
    extra_hits: dict[str, list[int]] = {p.pattern.decode(errors="replace"): [] for p in extra}
    extra_counts: Counter[str] = Counter()
    digest = hashlib.sha256()

    tail = b""
    base = 0
    read = 0
    with image.open("rb") as fh:
        while True:
            chunk = fh.read(CHUNK)
            if not chunk:
                break
            digest.update(chunk)
            read += len(chunk)
            buf = tail + chunk
            # Offset in the image of buf[0].
            buf_start = base

            def new_match(match: re.Match) -> bool:
                return not tail or match.end() > len(tail)

            for m in ONION_RE.finditer(buf):
                if not new_match(m):
                    continue
                addr = m.group(0).lower()
                onion_counts[addr] += 1
                onion_hits.setdefault(addr, [])
                if len(onion_hits[addr]) < 20:  # cap: we want proof, not a dump
                    onion_hits[addr].append(buf_start + m.start())

            for m in AUTH_CRED_RE.finditer(buf):
                if not new_match(m):
                    continue
                key = (m.group(1).lower(), m.group(2).lower())
                auth_counts[key] += 1
                auth_creds.setdefault(key, [])
                if len(auth_creds[key]) < 20:
                    auth_creds[key].append(buf_start + m.start())

            for m in UTF16_ONION_RE.finditer(buf):
                if not new_match(m):
                    continue
                name = m.group(0).replace(b"\x00", b"").lower()
                utf16_counts[name] += 1
                utf16_hits.setdefault(name, [])
                if len(utf16_hits[name]) < 20:
                    utf16_hits[name].append(buf_start + m.start())

            for name, rx in MARKER_RE.items():
                for m in rx.finditer(buf):
                    if not new_match(m):
                        continue
                    marker_counts[name] += 1
                    if len(marker_hits[name]) < 20:
                        marker_hits[name].append(buf_start + m.start())

            for rx in extra:
                key = rx.pattern.decode(errors="replace")
                for m in rx.finditer(buf):
                    if not new_match(m):
                        continue
                    extra_counts[key] += 1
                    if len(extra_hits[key]) < 20:
                        extra_hits[key].append(buf_start + m.start())

            tail = buf[-OVERLAP:]
            base = buf_start + len(buf) - len(tail)

            pct = 100.0 * read / size if size else 0
            print(
                f"\r  scanned {read / 2**30:6.2f} GiB / {size / 2**30:.2f} GiB "
                f"({pct:5.1f}%)  onion addrs: {len(onion_hits)}  "
                f"auth creds: {len(auth_creds)}",
                end="",
                file=sys.stderr,
                flush=True,
            )
    print(file=sys.stderr)

    return {
        "image": str(image),
        "image_bytes": size,
        "image_sha256": digest.hexdigest(),
        "onion_addresses": {
            addr.decode(): {"occurrences": onion_counts[addr], "first_offsets": offs}
            for addr, offs in sorted(onion_hits.items())
        },
        "client_auth_credentials": [
            {
                "onion_address": addr.decode() + ".onion",
                "x25519_private_key": key.decode(),
                "occurrences": auth_counts[(addr, key)],
                "first_offsets": offs,
            }
            for (addr, key), offs in sorted(auth_creds.items())
        ],
        "utf16_filenames": {
            name.decode(): {"occurrences": utf16_counts[name], "first_offsets": offs}
            for name, offs in sorted(utf16_hits.items())
        },
        "tor_markers": {
            k: {"occurrences": marker_counts[k], "first_offsets": v}
            for k, v in marker_hits.items()
            if v
        },
        "extra_patterns": {
            k: {"occurrences": extra_counts[k], "first_offsets": v}
            for k, v in extra_hits.items()
            if v
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("image", type=Path, help="Disk image or block device to scan")
    parser.add_argument("--out", type=Path, default=None, help="Write JSON report here")
    parser.add_argument(
        "--extra-pattern",
        action="append",
        default=[],
        help="Additional regex to search for (repeatable)",
    )
    parser.add_argument(
        "--custody-log", type=Path, default=None, help="Append a chain-of-custody entry to this log"
    )
    args = parser.parse_args()

    if not args.image.exists():
        print(f"error: {args.image} not found", file=sys.stderr)
        return 1

    extra = [re.compile(p.encode()) for p in args.extra_pattern]

    print(f"=== TRANCE Module B - raw disk carve ===\nimage: {args.image}\n")
    report = scan(args.image, extra)

    creds = report["client_auth_credentials"]
    print(f"\n*** Tor client-auth credentials recovered: {len(creds)} ***")
    for c in creds:
        print(f"  hidden service : {c['onion_address']}")
        print(f"  x25519 privkey : {c['x25519_private_key']}")
        print(
            f"  found at       : x{c['occurrences']}, "
            f"{', '.join(f'0x{o:x}' for o in c['first_offsets'][:6])}"
        )
    if not creds:
        print("  (none)")

    fnames = report["utf16_filenames"]
    print(f"\nUTF-16 onion filenames (MFT / directory index entries): {len(fnames)}")
    for name, info in fnames.items():
        print(f"  {name}  x{info['occurrences']}  first @ 0x{info['first_offsets'][0]:x}")
    if not fnames:
        print("  (none)")

    addrs = report["onion_addresses"]
    print(f"\n.onion addresses found: {len(addrs)}")
    for addr, info in sorted(addrs.items(), key=lambda kv: -kv[1]["occurrences"]):
        print(f"  {addr}  x{info['occurrences']}  " f"first @ 0x{info['first_offsets'][0]:x}")
    if not addrs:
        print("  (none)")

    markers = report["tor_markers"]
    print(f"\nTor presence markers: {len(markers)} type(s)")
    for name, info in markers.items():
        print(f"  {name:20s} x{info['occurrences']}  first @ 0x{info['first_offsets'][0]:x}")
    if not markers:
        print("  (none)")

    for key, info in report["extra_patterns"].items():
        print(f"\nextra /{key}/: x{info['occurrences']} first @ 0x{info['first_offsets'][0]:x}")

    print()
    if creds:
        print(
            "CONCLUSION: Tor client-authorisation credentials were recovered from disk, "
            "naming\nthe specific hidden service(s) above in plaintext. Unlike the "
            "browser profile,\nthis file is written by the Tor daemon and is NOT subject "
            "to Tor Browser's\npermanent-private-browsing policy -- it persists across "
            "shutdown. This attributes\naccess to a named onion service from disk "
            "evidence alone."
        )
    elif addrs:
        print(
            "CONCLUSION: .onion address(es) recovered from raw disk bytes. Because "
            "this scan\nignores the filesystem, a hit outside any live file indicates "
            "residue in slack or\nunallocated space -- correlate the offsets against "
            "the filesystem to determine which."
        )
    elif markers:
        print(
            "CONCLUSION: no .onion address survives in raw bytes, but Tor presence "
            "markers do.\nThe software's execution is provable from disk; the specific "
            "destination is not."
        )
    else:
        print("CONCLUSION: no Tor residue recoverable at the byte level.")

    if args.custody_log:
        log = CustodyLog(args.custody_log)
        log.record(
            CustodyEntry(
                artifact_path=str(args.image),
                sha256="(not hashed: multi-GB image, see acquisition manifest)",
                action="analyzed",
                notes="carve_onion_strings.py raw byte scan for .onion / Tor markers",
            )
        )
        log.save()

    if args.out:
        args.out.write_text(json.dumps(report, indent=2))
        print(f"\nJSON report written to {args.out}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
