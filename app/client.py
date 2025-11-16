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
        email = "alice2@example.com"
        username = "alice2"
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

        # Parse login response
        try:
            login_resp = json.loads(resp_plain.decode("utf-8"))
        except Exception:
            print("[LOGIN] invalid JSON in server response")
            return

        if login_resp.get("status") != "ok":
            print("[LOGIN] login failed, not establishing session key")
            return

        # --- Session key establishment (post-login DH) ---
        try:
            print(f"[SESSION_DH] waiting for server session public key from {addr}")
            session_server_dh_pub_bytes = recv_dh_pub(conn)
        except Exception as e:
            print(f"[SESSION_DH_ERROR] from {addr}: {e}")
            return

        session_server_dh_pub = load_peer_public_key(session_server_dh_pub_bytes)

        print(f"[SESSION_DH] generating client session keypair for {addr}")
        session_client_dh = generate_dh_keypair()
        print(f"[SESSION_DH] sending client session public key to {addr}")
        send_dh_pub(conn, session_client_dh.public_bytes)

        session_aes_key = derive_shared_key(session_client_dh.private_key, session_server_dh_pub)
        print(f"[SESSION_DH] derived session AES key for {addr}: {session_aes_key.hex()}")

        # Receive encrypted "session ready" message
        session_len_data = conn.recv(4)
        if not session_len_data:
            print("[SESSION] no session-ready response from server")
            return
        (session_len,) = struct.unpack("!I", session_len_data)
        session_ct = conn.recv(session_len)
        session_plain = aes_decrypt_ecb(session_aes_key, session_ct)
        print("[SESSION] server session message:", session_plain.decode("utf-8"))

        # TODO: use session_aes_key for actual chat messages

if __name__ == "__main__":
    main()
    print("Client exited.")
