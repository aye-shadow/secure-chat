"""Client skeleton — plain TCP; no TLS. See assignment spec."""

import socket
import struct
import json
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
from app.crypto.aes import aes_encrypt_ecb, aes_decrypt_ecb  

SERVER_HOSTNAME = "127.0.0.1"


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

        # 3) DH: receive ServerHello (server DH public key)
        try:
            print(f"[DH] waiting for server public key from {addr}")
            server_dh_pub_bytes = recv_dh_pub(conn)
        except Exception as e:
            print(f"[DH_ERROR] from {addr}: {e}")
            return

        server_dh_pub = load_peer_public_key(server_dh_pub_bytes)

        # 4) generate client DH keypair and send Hello
        print(f"[DH] generating client keypair for {addr}")
        client_dh = generate_dh_keypair()
        print(f"[DH] sending client public key to {addr}")
        send_dh_pub(conn, client_dh.public_bytes)

        # 5) derive shared AES key
        aes_key = derive_shared_key(client_dh.private_key, server_dh_pub)
        print(f"[DH] derived AES key for {addr}: {aes_key.hex()}")

        # --- Registration step ---
        # Collect registration data (hard-coded here; replace with input() if needed)
        email = "alice1@example.com"
        username = "alice1"
        password = "supersecret"

        reg_payload = {
            "type": "register",
            "email": email,
            "username": username,
            "password": password,
        }
        reg_json = json.dumps(reg_payload).encode("utf-8")

        # Encrypt with AES-128-ECB (assignment helper)
        ciphertext = aes_encrypt_ecb(aes_key, reg_json)

        # Send length-prefixed ciphertext: [4-byte big-endian length][ciphertext]
        conn.sendall(struct.pack("!I", len(ciphertext)) + ciphertext)
        print(f"[REG] registration payload sent to {addr}")

        # --- Login step ---
        login_payload = {
            "type": "login",
            "username": username,
            "password": password,
        }
        login_json = json.dumps(login_payload).encode("utf-8")
        login_ct = aes_encrypt_ecb(aes_key, login_json)

        conn.sendall(struct.pack("!I", len(login_ct)) + login_ct)
        print(f"[LOGIN] login payload sent to {addr}")

        # Wait for encrypted login response
        resp_len_data = conn.recv(4)
        if not resp_len_data:
            print("[LOGIN] no response from server")
            return
        (resp_len,) = struct.unpack("!I", resp_len_data)
        resp_ct = conn.recv(resp_len)
        resp_plain = aes_decrypt_ecb(aes_key, resp_ct)
        print("[LOGIN] server response:", resp_plain.decode("utf-8"))

if __name__ == "__main__":
    main()
    print("Client exited.")
