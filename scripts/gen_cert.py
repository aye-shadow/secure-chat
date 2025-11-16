"""Issue server/client cert signed by Root CA (SAN=DNSName(CN))."""
from __future__ import annotations

import argparse
import datetime
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID


def load_ca(ca_dir: Path):
    ca_cert = x509.load_pem_x509_certificate((ca_dir / "ca_cert.pem").read_bytes())
    ca_key = serialization.load_pem_private_key(
        (ca_dir / "ca_key.pem").read_bytes(), password=None
    )
    return ca_cert, ca_key


def issue_cert(cn: str, out_dir: Path, ca_dir: Path) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)

    ca_cert, ca_key = load_ca(ca_dir)

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    now = datetime.datetime.utcnow()

    san = x509.SubjectAlternativeName([x509.DNSName(cn)])

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=365))  # 1 year
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(san, critical=False)
        .sign(private_key=ca_key, algorithm=hashes.SHA256())
    )

    key_path = out_dir / "key.pem"
    cert_path = out_dir / "cert.pem"

    key_bytes = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    cert_bytes = cert.public_bytes(encoding=serialization.Encoding.PEM)

    key_path.write_bytes(key_bytes)
    cert_path.write_bytes(cert_bytes)

    print(f"[+] Wrote leaf key: {key_path}")
    print(f"[+] Wrote leaf cert: {cert_path}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Issue leaf certificate")
    parser.add_argument("--cn", required=True, help="Common Name / hostname")
    parser.add_argument(
        "--out",
        required=True,
        help="Output directory for key/cert, e.g. certs/server",
    )
    parser.add_argument(
        "--ca-dir",
        default="certs/ca",
        help="Directory containing ca_key.pem and ca_cert.pem",
    )
    args = parser.parse_args()

    issue_cert(args.cn, Path(args.out), Path(args.ca_dir))


if __name__ == "__main__":
    main()