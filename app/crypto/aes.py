"""AES-128(ECB)+PKCS#7 helpers (use library)."""
from __future__ import annotations

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


BLOCK_SIZE = 16  # bytes


def _pkcs7_pad(data: bytes) -> bytes:
    pad_len = BLOCK_SIZE - (len(data) % BLOCK_SIZE)
    return data + bytes([pad_len]) * pad_len


def _pkcs7_unpad(data: bytes) -> bytes:
    if not data:
        raise ValueError("empty data for pkcs7_unpad")
    pad_len = data[-1]
    if pad_len < 1 or pad_len > BLOCK_SIZE:
        raise ValueError("bad padding length")
    if data[-pad_len:] != bytes([pad_len]) * pad_len:
        raise ValueError("bad padding bytes")
    return data[:-pad_len]


def aes_encrypt_ecb(key: bytes, plaintext: bytes) -> bytes:
    if len(key) != 16:
        raise ValueError("AES-128 key must be 16 bytes")
    cipher = Cipher(algorithms.AES(key), modes.ECB())
    encryptor = cipher.encryptor()
    padded = _pkcs7_pad(plaintext)
    return encryptor.update(padded) + encryptor.finalize()


def aes_decrypt_ecb(key: bytes, ciphertext: bytes) -> bytes:
    if len(key) != 16:
        raise ValueError("AES-128 key must be 16 bytes")
    cipher = Cipher(algorithms.AES(key), modes.ECB())
    decryptor = cipher.decryptor()
    padded = decryptor.update(ciphertext) + decryptor.finalize()
    return _pkcs7_unpad(padded)