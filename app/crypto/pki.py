"""X.509 validation: signed-by-CA, validity window, CN/SAN."""
from __future__ import annotations

import datetime
from typing import Optional

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.x509.oid import NameOID


class BadCertificate(Exception):
    """Raised when certificate validation fails."""


def load_certificate_pem(path: str) -> x509.Certificate:
    return x509.load_pem_x509_certificate(open(path, "rb").read())


def verify_cert_validity(cert: x509.Certificate, at: Optional[datetime.datetime] = None):
    now = at or datetime.datetime.utcnow()
    if now < cert.not_valid_before or now > cert.not_valid_after:
        raise BadCertificate("Certificate is expired or not yet valid")


def verify_cert_signed_by_ca(cert: x509.Certificate, ca_cert: x509.Certificate):
    ca_public_key = ca_cert.public_key()
    try:
        ca_public_key.verify(
            cert.signature,
            cert.tbs_certificate_bytes,
            padding.PKCS1v15(),
            cert.signature_hash_algorithm,
        )
    except Exception as e:  # cryptography-specific exceptions
        raise BadCertificate("Certificate not signed by trusted CA") from e


def _get_cert_hostnames(cert: x509.Certificate) -> set[str]:
    names: set[str] = set()
    # SAN
    try:
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        for name in san.value.get_values_for_type(x509.DNSName):
            names.add(name)
    except x509.ExtensionNotFound:
        pass

    # CN as fallback
    for attr in cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME):
        names.add(attr.value)

    return names


def verify_cert_hostname(cert: x509.Certificate, expected_hostname: str):
    hostnames = _get_cert_hostnames(cert)
    if expected_hostname not in hostnames:
        raise BadCertificate(
            f"Hostname mismatch: {expected_hostname!r} not in {sorted(hostnames)!r}"
        )


def verify_peer_certificate(
    peer_cert: x509.Certificate,
    ca_cert: x509.Certificate,
    expected_hostname: str,
    at: Optional[datetime.datetime] = None,
) -> None:
    """Run all PKI checks; raise BadCertificate if any fails."""
    verify_cert_validity(peer_cert, at=at)
    verify_cert_signed_by_ca(peer_cert, ca_cert)
    verify_cert_hostname(peer_cert, expected_hostname)