"""Client skeleton — plain TCP; no TLS. See assignment spec."""

import socket
import struct
from app.crypto.pki import (
    load_certificate_pem,
    verify_peer_certificate,
    BadCertificate,
)

SERVER_HOSTNAME = "127.0.0.1"


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

def main():
    ca_cert = load_certificate_pem("certs/ca/ca_cert.pem")
    client_cert = load_certificate_pem("certs/client/cert.pem")

    client_cert_pem = open("certs/client/cert.pem", "rb").read()

    # plain TCP client
    with socket.create_connection((SERVER_HOSTNAME, 9000)) as conn:
        addr = conn.getpeername()
        print(f"Connected to server at {addr}")

        # 1) send our client certificate to server
        print(f"[SENDING_CERT] to {addr}")
        send_cert(conn, client_cert_pem)

        # 2) receive server cert bytes
        try:
            peer_cert_pem = recv_cert(conn)
            print(f"[CONN] from {addr}")
        except Exception as e:
            print(f"[HANDSHAKE_ERROR] from {addr}: {e}")
            return

        from cryptography import x509

        server_cert = x509.load_pem_x509_certificate(peer_cert_pem)
        try:
            verify_peer_certificate(
                server_cert,
                ca_cert,
                expected_hostname="server.local",
            )
            print(f"[CERT_OK] from {addr}")
        except BadCertificate as e:
            # reject + log
            print(f"[BAD_CERT] from {addr}: {e}")
            return

        # ...continue handshake (DH, AES, etc.)...

if __name__ == "__main__":
    main()
    print("Client exited.")
