"""Server skeleton — plain TCP; no TLS. See assignment spec."""
import socket
import struct
from app.crypto.pki import (
    load_certificate_pem,
    verify_peer_certificate,
    BadCertificate,
)

SERVER_HOSTNAME = "server.local"


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
    server_cert = load_certificate_pem("certs/server/cert.pem")

    server_cert_pem = open("certs/server/cert.pem", "rb").read()

    # plain TCP server
    with socket.create_server(("0.0.0.0", 9000)) as srv:
        print("Server listening on port 9000...")

        while True:
            conn, addr = srv.accept()
            with conn:
                # 1) receive client cert bytes
                try:
                    peer_cert_pem = recv_cert(conn)
                    print(f"[CONN] from {addr}")
                except Exception as e:
                    print(f"[HANDSHAKE_ERROR] from {addr}: {e}")
                    continue

                from cryptography import x509

                client_cert = x509.load_pem_x509_certificate(peer_cert_pem)
                try:
                    verify_peer_certificate(
                        client_cert,
                        ca_cert,
                        expected_hostname="client.local",
                    )
                    print(f"[CERT_OK] from {addr}")
                except BadCertificate as e:
                    # reject + log
                    print(f"[BAD_CERT] from {addr}: {e}")
                    # send protocol error, then close
                    continue

                # 2) send our server certificate to client
                print(f"[SENDING_CERT] to {addr}")
                send_cert(conn, server_cert_pem)

                # ...continue handshake (DH, AES, etc.)...

if __name__ == "__main__":
    main()
    print("Server exited.")