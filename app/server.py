"""Server skeleton — plain TCP; no TLS. See assignment spec."""
import socket
import json
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
from app.crypto.aes import aes_encrypt_ecb, aes_decrypt_ecb
from app.storage.db import create_user

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

                # --- Registration step ---
                # Receive length-prefixed ciphertext
                len_hdr = conn.recv(4)
                if not len_hdr:
                    print(f"[REG] no data from {addr}")
                    continue
                (ct_len,) = struct.unpack("!I", len_hdr)
                ciphertext = conn.recv(ct_len)
                if len(ciphertext) != ct_len:
                    print(f"[REG] incomplete registration ciphertext from {addr}")
                    continue

                # Decrypt registration JSON
                try:
                    reg_json = aes_decrypt_ecb(aes_key, ciphertext)
                    reg = json.loads(reg_json.decode("utf-8"))
                except Exception as e:
                    print(f"[REG_ERROR] bad registration payload from {addr}: {e}")
                    continue

                if reg.get("type") != "register":
                    print(f"[REG_ERROR] unexpected message type from {addr}: {reg!r}")
                    continue

                email = reg.get("email")
                username = reg.get("username")
                password = reg.get("password")

                if not (email and username and password):
                    print(f"[REG_ERROR] missing fields from {addr}: {reg!r}")
                    continue

                try:
                    create_user(email, username, password)
                    print(f"[REG_OK] user {username} registered from {addr}")
                except Exception as e:
                    print(f"[REG_DB_ERROR] could not create user {username}: {e}")
                    continue

                # --- Login step ---
                # Receive length-prefixed ciphertext again
                len_hdr = conn.recv(4)
                if not len_hdr:
                    print(f"[LOGIN] no data from {addr}")
                    continue
                (ct_len,) = struct.unpack("!I", len_hdr)
                ciphertext = conn.recv(ct_len)
                if len(ciphertext) != ct_len:
                    print(f"[LOGIN] incomplete login ciphertext from {addr}")
                    continue

                try:
                    login_json = aes_decrypt_ecb(aes_key, ciphertext)
                    login_msg = json.loads(login_json.decode("utf-8"))
                except Exception as e:
                    print(f"[LOGIN_ERROR] bad login payload from {addr}: {e}")
                    continue

                if login_msg.get("type") != "login":
                    print(f"[LOGIN_ERROR] unexpected message type from {addr}: {login_msg!r}")
                    continue

                login_user = login_msg.get("username")
                login_pwd = login_msg.get("password")

                if not (login_user and login_pwd):
                    print(f"[LOGIN_ERROR] missing fields from {addr}: {login_msg!r}")
                    continue

                from app.storage.db import verify_user

                try:
                    ok = verify_user(login_user, login_pwd)
                    if ok:
                        print(f"[LOGIN_OK] user {login_user} logged in from {addr}")
                        resp = json.dumps({"status": "ok"}).encode("utf-8")
                    else:
                        print(f"[LOGIN_FAIL] invalid credentials for {login_user} from {addr}")
                        resp = json.dumps({"status": "error", "reason": "invalid_credentials"}).encode("utf-8")

                    resp_ct = aes_encrypt_ecb(aes_key, resp)
                    conn.sendall(struct.pack("!I", len(resp_ct)) + resp_ct)
                except Exception as e:
                    print(f"[LOGIN_DB_ERROR] for user {login_user}: {e}")
                    resp = json.dumps({"status": "error", "reason": "server_error"}).encode("utf-8")
                    resp_ct = aes_encrypt_ecb(aes_key, resp)
                    conn.sendall(struct.pack("!I", len(resp_ct)) + resp_ct)
                    continue

if __name__ == "__main__":
    main()
    print("Server exited.")