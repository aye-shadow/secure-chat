"""Helper signatures: now_ms, b64e, b64d, sha256_hex."""
from __future__ import annotations

import base64
import time
from hashlib import sha256
import struct
import socket

def now_ms() -> int:
    return int(time.time() * 1000)


def b64e(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")


def b64d(s: str) -> bytes:
    return base64.b64decode(s.encode("ascii"))


def sha256_hex(data: bytes) -> str:
    return sha256(data).hexdigest()

def recv_exact(conn: socket.socket, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = conn.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("peer closed while reading")
        buf += chunk
    return buf


def recv_cert(conn: socket.socket) -> bytes:
    # 4‑byte big‑endian length + PEM bytes
    length_bytes = recv_exact(conn, 4)
    (length,) = struct.unpack("!I", length_bytes)
    return recv_exact(conn, length)


def send_cert(conn: socket.socket, cert_pem: bytes) -> None:
    conn.sendall(struct.pack("!I", len(cert_pem)) + cert_pem)

def recv_dh_pub(conn: socket.socket) -> bytes:
    """4-byte length + DH public key bytes."""
    length_bytes = recv_exact(conn, 4)
    (length,) = struct.unpack("!I", length_bytes)
    return recv_exact(conn, length)


def send_dh_pub(conn: socket.socket, dh_pub: bytes) -> None:
    conn.sendall(struct.pack("!I", len(dh_pub)) + dh_pub)