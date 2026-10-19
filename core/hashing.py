"""SHA-256 hashing utilities for evidence integrity verification."""

from __future__ import annotations

import hashlib
from collections.abc import Callable
from pathlib import Path


def hash_file(
    path: Path, chunk_size: int = 65536, on_chunk: Callable[[int], None] | None = None
) -> str:
    """SHA-256 of the file. on_chunk(bytes_read) after each chunk, for progress reporting."""
    digest = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(chunk_size), b""):
            digest.update(chunk)
            if on_chunk:
                on_chunk(len(chunk))
    return digest.hexdigest()


def hash_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()
