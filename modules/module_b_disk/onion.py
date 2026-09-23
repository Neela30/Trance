"""Validate v3 onion addresses so carved 56-character strings are not mistaken for one.

A v3 address is base32 of: 32-byte ed25519 public key || 2-byte checksum ||
version byte 0x03, where checksum = SHA3-256(".onion checksum" || pubkey ||
version)[:2]. Any 56 base32 characters look like an address to a regex
(a long asset filename did, on real evidence); the checksum settles it.
"""

from __future__ import annotations

import base64
import binascii
import hashlib

VERSION = b"\x03"


def is_v3_onion(address: str) -> bool:
    host = address.lower().removesuffix(".onion")
    if len(host) != 56:
        return False
    try:
        raw = base64.b32decode(host.upper())
    except (binascii.Error, ValueError):
        return False
    if len(raw) != 35 or raw[34:35] != VERSION:
        return False
    pubkey, checksum = raw[:32], raw[32:34]
    expected = hashlib.sha3_256(b".onion checksum" + pubkey + VERSION).digest()[:2]
    return checksum == expected
