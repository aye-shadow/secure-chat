from __future__ import annotations
"""Classic DH helpers + Trunc16(SHA256(Ks)) derivation."""

from dataclasses import dataclass
from hashlib import sha256

from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives import serialization

# --- Fixed DH group (same every time, both sides) ---
# 512-bit safe prime for demo (NOT production secure).
_DH_P_HEX = (
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
    "E485B576625E7EC6F44C42E9A63A3620FFFFFFFFFFFFFFFF"
)
DH_P = int(_DH_P_HEX, 16)
DH_G = 2

# Create DHParameters from the fixed numbers
DH_PARAMETERS = dh.DHParameterNumbers(DH_P, DH_G).parameters()


@dataclass
class DHKeyPair:
    private_key: dh.DHPrivateKey
    public_bytes: bytes  # serialized public key (PEM)

    @property
    def public_key(self) -> dh.DHPublicKey:
        return self.private_key.public_key()


def generate_dh_parameters() -> dh.DHParameters:
    return DH_PARAMETERS


def generate_dh_keypair(params: dh.DHParameters | None = None) -> DHKeyPair:
    if params is None:
        params = DH_PARAMETERS
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
    """Return 16-byte AES key = Trunc16(SHA256(shared_secret_bytes))."""
    my_params = my_priv.private_numbers().public_numbers.parameter_numbers
    peer_params = peer_pub.public_numbers().parameter_numbers

    print("[DH_DEBUG] my p =", hex(my_params.p), "g =", my_params.g)
    print("[DH_DEBUG] peer p =", hex(peer_params.p), "g =", peer_params.g)

    if my_params.p != peer_params.p or my_params.g != peer_params.g:
        raise ValueError("DH parameter mismatch between peers")

    shared = my_priv.exchange(peer_pub)
    digest = sha256(shared).digest()
    return digest[:16]
