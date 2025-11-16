import struct
from hashlib import sha256

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

RECEIPT_PATH = "server_session_receipt.txt"   # or client_session_receipt.txt
CERT_PATH    = "certs/server/cert.pem"        # or certs/client/cert.pem

def load_public_key(cert_path: str):
    cert = x509.load_pem_x509_certificate(open(cert_path, "rb").read())
    return cert.public_key()

def verify_session_receipt():
    # 1) read receipt, split transcript / hash / sig
    with open(RECEIPT_PATH, "r", encoding="utf-8") as f:
        lines = f.readlines()

    # find HASH and SIG lines
    transcript_lines = []
    hash_hex = None
    sig_hex = None
    for line in lines:
        if line.startswith("HASH:"):
            hash_hex = line.strip().split("HASH:")[1]
        elif line.startswith("SIG:"):
            sig_hex = line.strip().split("SIG:")[1]
        elif line.startswith("TRANSCRIPT:") or not line.strip():
            continue
        else:
            transcript_lines.append(line)

    if hash_hex is None or sig_hex is None:
        raise ValueError("Receipt missing HASH or SIG")

    # recompute transcript hash
    transcript_bytes = "".join(transcript_lines).encode("utf-8")
    recomputed_hash = sha256(transcript_bytes).digest()
    stored_hash = bytes.fromhex(hash_hex)

    print("[*] Stored HASH:", hash_hex)
    print("[*] Recompt HASH:", recomputed_hash.hex())
    print("[*] Hash matches? ", stored_hash == recomputed_hash)

    # 2) verify Session Receipt signature
    sig = bytes.fromhex(sig_hex)
    pubkey = load_public_key(CERT_PATH)

    pubkey.verify(
        sig,
        stored_hash,
        padding.PKCS1v15(),
        hashes.SHA256(),
    )
    print("[*] Session Receipt signature is VALID")

if __name__ == "__main__":
    verify_session_receipt()