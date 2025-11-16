from __future__ import annotations
"""Classic DH helpers + Trunc16(SHA256(Ks)) derivation."""

import os
from dataclasses import dataclass
from hashlib import sha256

from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives import serialization


# You can use standard MODP group; here we just generate on the fly for simplicity
# For production/assignment you may want fixed parameters.
DH_KEY_SIZE = 2048


@dataclass
class DHKeyPair:
    private_key: dh.DHPrivateKey
    public_bytes: bytes  # serialized public key (PEM)

    @property
    def public_key(self) -> dh.DHPublicKey:
        return self.private_key.public_key()


def generate_dh_parameters() -> dh.DHParameters:
    """Generate DH parameters. Cache in memory in real app."""
    return dh.generate_parameters(generator=2, key_size=DH_KEY_SIZE)


def generate_dh_keypair(params: dh.DHParameters | None = None) -> DHKeyPair:
    if params is None:
        params = generate_dh_parameters()
    priv = params.generate_private_key()
    pub = priv.public_key()
    pub_bytes = pub.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return DHKeyPair(private_key=priv, public_bytes=pub_bytes)


def load_peer_public_key(pub_bytes: bytes) -> dh.DHPublicKey:
    return serialization.load_pem_public_key(pub_bytes)


def derive_shared_key(my_priv: dh.DHPrivateKey, peer_pub: dh.DHPublicKey) -> bytes:
    """Return 16‑byte AES key = Trunc16(SHA256(shared_secret_bytes))."""
    shared = my_priv.exchange(peer_pub)  # big integer -> bytes
    digest = sha256(shared).digest()
    return digest[:16]