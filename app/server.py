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
from app.storage.db import create_user, verify_user
from app.crypto.chat import (
    load_private_key,
    build_chat_message,
    parse_chat_message,
)
from cryptography.hazmat.primitives import serialization

SERVER_HOSTNAME = "server.local"


def main():
    ca_cert = load_certificate_pem("certs/ca/ca_cert.pem")
    server_cert = load_certificate_pem("certs/server/cert.pem")
    server_privkey = load_private_key("certs/server/key.pem")  

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
                client_pubkey = client_cert.public_key()

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

                # --- Session key establishment (post-login DH) ---
                if ok:
                    print(f"[SESSION_DH] generating server session keypair for {addr}")
                    session_server_dh = generate_dh_keypair()
                    print(f"[SESSION_DH] sending server session public key to {addr}")
                    send_dh_pub(conn, session_server_dh.public_bytes)

                    try:
                        print(f"[SESSION_DH] waiting for client session public key from {addr}")
                        client_session_dh_pub_bytes = recv_dh_pub(conn)
                    except Exception as e:
                        print(f"[SESSION_DH_ERROR] from {addr}: {e}")
                        continue

                    client_session_dh_pub = load_peer_public_key(client_session_dh_pub_bytes)
                    session_aes_key = derive_shared_key(session_server_dh.private_key, client_session_dh_pub)
                    print(f"[SESSION_DH] derived session AES key for {addr}: {session_aes_key.hex()}")

                    # Example: send an encrypted "session ready" message with the new key
                    session_msg = json.dumps({"type": "session", "status": "ready"}).encode("utf-8")
                    session_ct = aes_encrypt_ecb(session_aes_key, session_msg)
                    conn.sendall(struct.pack("!I", len(session_ct)) + session_ct)

                    # --- Encrypted chat loop (data plane) ---
                    print(f"[CHAT] starting secure chat with {addr}")
                    server_seq = 0
                    last_client_seq = 0
                    transcript = []  # append-only transcript of metadata lines
                    while True:
                        # Receive one chat message from client
                        hdr = conn.recv(4)
                        if not hdr:
                            print(f"[CHAT] client {addr} disconnected")
                            break
                        (msg_len,) = struct.unpack("!I", hdr)
                        body = conn.recv(msg_len)
                        if len(body) != msg_len:
                            print(f"[CHAT] incomplete chat message from {addr}")
                            break

                        try:
                            plaintext, last_client_seq = parse_chat_message(
                                hdr + body, session_aes_key, client_pubkey, last_client_seq
                            )
                            print(f"[CHAT_RX] from {addr}: {plaintext!r}")

                            # Log inbound message metadata
                            import time
                            ts = time.time()
                            line = f"RX|{last_client_seq}|{ts}|client|{plaintext}\n"
                            transcript.append(line)
                        except Exception as e:
                            print(f"[CHAT_ERROR] invalid chat message from {addr}: {e}")
                            break

                        # Example echo / server reply
                        reply_text = f"Echo: {plaintext}"
                        server_seq += 1
                        reply_wire = build_chat_message(
                            server_seq, session_aes_key, server_privkey, reply_text
                        )
                        conn.sendall(reply_wire)

                        # Log outbound message metadata
                        ts = time.time()
                        line = f"TX|{server_seq}|{ts}|client|{reply_text}\n"
                        transcript.append(line)
                    # end chat loop

                    # --- Session Receipt (server side) ---
                    from hashlib import sha256
                    from cryptography.hazmat.primitives import hashes
                    from cryptography.hazmat.primitives.asymmetric import padding as asym_padding

                    transcript_bytes = "".join(transcript).encode("utf-8")
                    transcript_hash = sha256(transcript_bytes).digest()

                    server_receipt_sig = server_privkey.sign(
                        transcript_hash,
                        asym_padding.PKCS1v15(),
                        hashes.SHA256(),
                    )

                    print("[RECEIPT] server transcript SHA256:", transcript_hash.hex())
                    print("[RECEIPT] server signature:", server_receipt_sig.hex())

                    with open("server_session_receipt.txt", "w", encoding="utf-8") as f:
                        f.write("TRANSCRIPT:\n")
                        f.writelines(transcript)
                        f.write("\nHASH:" + transcript_hash.hex() + "\n")
                        f.write("SIG:" + server_receipt_sig.hex() + "\n")

if __name__ == "__main__":
    main()
    print("Server exited.")