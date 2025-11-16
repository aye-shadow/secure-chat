"""Server skeleton — plain TCP; no TLS. See assignment spec."""
import socket
import struct
from app.crypto.pki import (
    load_certificate_pem,
    verify_peer_certificate,
    BadCertificate,
)
from app.crypto.dh import (
    generate_dh_keypair,
    load_peer_public_key,
    derive_shared_key,
)
from app.common.utils import recv_cert, send_cert, recv_dh_pub, send_dh_pub

SERVER_HOSTNAME = "server.local"


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

                # 3) DH: server generates keypair and sends ServerHello
                print(f"[DH] generating server keypair for {addr}")
                server_dh = generate_dh_keypair()
                print(f"[DH] sending server public key to {addr}")
                send_dh_pub(conn, server_dh.public_bytes)

                # 4) receive client's DH public key (Hello)
                try:
                    print(f"[DH] waiting for client public key from {addr}")
                    client_dh_pub_bytes = recv_dh_pub(conn)
                except Exception as e:
                    print(f"[DH_ERROR] from {addr}: {e}")
                    continue

                # 5) derive shared AES key
                client_dh_pub = load_peer_public_key(client_dh_pub_bytes)
                aes_key = derive_shared_key(server_dh.private_key, client_dh_pub)
                print(f"[DH] derived AES key for {addr}: {aes_key.hex()}")

                # ...continue handshake (AES, IV, MAC, etc.)...

if __name__ == "__main__":
    main()
    print("Server exited.")