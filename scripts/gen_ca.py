"""Create Root CA (RSA + self-signed X.509) using cryptography."""
from __future__ import annotations

import argparse
import datetime
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID


def generate_ca(name: str, out_dir: Path) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    subject = issuer = x509.Name(
        [x509.NameAttribute(NameOID.COMMON_NAME, name)]
    )
    now = datetime.datetime.utcnow()

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=3650))  # ~10 years
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(private_key=key, algorithm=hashes.SHA256())
    )

    key_path = out_dir / "ca_key.pem"
    cert_path = out_dir / "ca_cert.pem"

    key_bytes = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    cert_bytes = cert.public_bytes(encoding=serialization.Encoding.PEM)

    key_path.write_bytes(key_bytes)
    cert_path.write_bytes(cert_bytes)

    print(f"[+] Wrote CA key: {key_path}")
    print(f"[+] Wrote CA cert: {cert_path}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Create Root CA")
    parser.add_argument("--name", required=True, help="CA Common Name")
    parser.add_argument(
        "--out",
        default="certs/ca",
        help="Output directory for CA key/cert (default: certs/ca)",
    )
    args = parser.parse_args()

    generate_ca(args.name, Path(args.out))


if __name__ == "__main__":
    main()