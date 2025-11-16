import json
import time
import struct
from hashlib import sha256

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding as asy_padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


def pkcs7_pad(data: bytes, block_size: int = 16) -> bytes:
    pad_len = block_size - (len(data) % block_size)
    return data + bytes([pad_len] * pad_len)


def pkcs7_unpad(data: bytes, block_size: int = 16) -> bytes:
    if not data or len(data) % block_size != 0:
        raise ValueError("Invalid PKCS#7 padding")
    pad_len = data[-1]
    if pad_len < 1 or pad_len > block_size:
        raise ValueError("Invalid PKCS#7 padding length")
    if data[-pad_len:] != bytes([pad_len] * pad_len):
        raise ValueError("Invalid PKCS#7 padding bytes")
    return data[:-pad_len]


def aes_encrypt_cbc(key: bytes, plaintext: bytes, iv: bytes) -> bytes:
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    enc = cipher.encryptor()
    return enc.update(plaintext) + enc.finalize()


def aes_decrypt_cbc(key: bytes, ciphertext: bytes, iv: bytes) -> bytes:
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    dec = cipher.decryptor()
    return dec.update(ciphertext) + dec.finalize()


def load_private_key(path: str):
    with open(path, "rb") as f:
        key_data = f.read()
    return serialization.load_pem_private_key(key_data, password=None)


def sign_digest(private_key, digest: bytes) -> bytes:
    return private_key.sign(
        digest,
        asy_padding.PKCS1v15(),
        hashes.SHA256(),
    )


def verify_digest(public_key, digest: bytes, signature: bytes) -> None:
    public_key.verify(
        signature,
        digest,
        asy_padding.PKCS1v15(),
        hashes.SHA256(),
    )


def build_chat_message(seqno: int, session_key: bytes, private_key, plaintext: str) -> bytes:
    """
    Build a length-prefixed chat message:
    outer framing: [4-byte big-endian length][JSON]
    JSON:
      {
        "seqno": int,
        "ts": float,
        "iv": base16,
        "ct": base16,
        "sig": base16,
      }
    """
    import os

    ts = time.time()
    iv = os.urandom(16)

    pt_bytes = plaintext.encode("utf-8")
    padded = pkcs7_pad(pt_bytes, 16)
    ct = aes_encrypt_cbc(session_key, padded, iv)

    # h = SHA256(seqno || timestamp || ciphertext)
    seq_bytes = struct.pack("!Q", seqno)  # 8-byte unsigned
    ts_bytes = struct.pack("!d", ts)      # 8-byte double
    h = sha256(seq_bytes + ts_bytes + ct).digest()

    sig = sign_digest(private_key, h)

    msg = {
        "seqno": seqno,
        "ts": ts,
        "iv": iv.hex(),
        "ct": ct.hex(),
        "sig": sig.hex(),
    }
    payload = json.dumps(msg).encode("utf-8")
    return struct.pack("!I", len(payload)) + payload


def parse_chat_message(data: bytes, session_key: bytes, public_key, last_seqno: int) -> tuple[str, int]:
    """
    Parse a length-prefixed chat message, verify signature and seqno,
    and return (plaintext_str, new_last_seqno).
    """
    import json

    if len(data) < 4:
        raise ValueError("Message too short")

    (msg_len,) = struct.unpack("!I", data[:4])
    body = data[4:]
    if len(body) != msg_len:
        raise ValueError("Incomplete message body")

    msg = json.loads(body.decode("utf-8"))
    seqno = int(msg["seqno"])
    ts = float(msg["ts"])
    iv = bytes.fromhex(msg["iv"])
    ct = bytes.fromhex(msg["ct"])
    sig = bytes.fromhex(msg["sig"])

    # Replay / ordering protection: seqno strictly increasing
    if seqno <= last_seqno:
        raise ValueError("Non-increasing sequence number")

    # Recompute h
    seq_bytes = struct.pack("!Q", seqno)
    ts_bytes = struct.pack("!d", ts)
    h = sha256(seq_bytes + ts_bytes + ct).digest()

    # Verify signature
    verify_digest(public_key, h, sig)

    padded = aes_decrypt_cbc(session_key, ct, iv)
    pt = pkcs7_unpad(padded, 16)
    return pt.decode("utf-8"), seqno