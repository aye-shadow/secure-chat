"""Helper signatures: now_ms, b64e, b64d, sha256_hex."""
from __future__ import annotations

import base64
import time
from hashlib import sha256


def now_ms() -> int:
    return int(time.time() * 1000)


def b64e(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")


def b64d(s: str) -> bytes:
    return base64.b64decode(s.encode("ascii"))


def sha256_hex(data: bytes) -> str:
    return sha256(data).hexdigest()