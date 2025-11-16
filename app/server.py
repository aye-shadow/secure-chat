"""Server skeleton — plain TCP; no TLS. See assignment spec."""
import socket
from app.crypto.pki import (
    load_certificate_pem,
    verify_peer_certificate,
    BadCertificate,
)

SERVER_HOSTNAME = "server.local"


def main():
    ca_cert = load_certificate_pem("certs/ca/ca_cert.pem")
    server_cert = load_certificate_pem("certs/server/cert.pem")

    # plain TCP server
    with socket.create_server(("0.0.0.0", 9000), reuse_port=True) as srv:
        while True:
            conn, addr = srv.accept()
            with conn:
                # 1) receive client cert bytes via your application protocol
                # ...existing code...
                peer_cert_pem = b"...read from conn..."  # TODO
                # ...existing code...

                from cryptography import x509

                client_cert = x509.load_pem_x509_certificate(peer_cert_pem)
                try:
                    verify_peer_certificate(
                        client_cert,
                        ca_cert,
                        expected_hostname="client.local",
                    )
                except BadCertificate as e:
                    # reject + log
                    print(f"[BAD_CERT] from {addr}: {e}")
                    # send protocol error, then close
                    continue

                # then send server_cert to client, etc.
                # ...continue handshake...


if __name__ == "__main__":
    main()