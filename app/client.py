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
from app.crypto.chat import (
    load_private_key,
    build_chat_message,
    parse_chat_message,
)
from cryptography.hazmat.primitives import serialization

SERVER_HOSTNAME = "127.0.0.1"


def main():
    ca_cert = load_certificate_pem("certs/ca/ca_cert.pem")
    client_cert = load_certificate_pem("certs/client/cert.pem")
    client_privkey = load_private_key("certs/client/key.pem")  

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
        server_pubkey = server_cert.public_key()

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
        email = "alice14@example.com"
        username = "alice14"
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

        # --- Encrypted chat loop (data plane) ---
        print("[CHAT] enter messages, or just press Enter to quit")
        client_seq = 0
        last_server_seq = 0
        transcript = []  # append-only transcript of metadata lines
        last_wire_msg = None  # for replay test
        last_text = None

        while True:
            try:
                text = input("> ")
            except EOFError:
                break
            if not text:
                break

            # # Special command: trigger replay of previous message
            # if text == "REPLAY":
            #     if last_wire_msg is None:
            #         print("[REPLAY] no previous message to replay")
            #         continue
            #     print("[REPLAY] resending previous message with old seqno")
            #     conn.sendall(last_wire_msg)

            #     # Log outbound replay metadata (note: same seqno as before)
            #     import time
            #     ts = time.time()
            #     line = f"TX|{client_seq}|{ts}|server|REPLAY({last_text})\n"
            #     transcript.append(line)

            #     # Try to receive server reply (expected to fail with REPLAY/SIG_FAIL)
            #     hdr = conn.recv(4)
            #     if not hdr:
            #         print("[CHAT] server closed connection after replay test")
            #         break
            #     (msg_len,) = struct.unpack("!I", hdr)
            #     body = conn.recv(msg_len)
            #     if len(body) != msg_len:
            #         print("[CHAT] incomplete reply from server after replay")
            #         break
            #     try:
            #         reply_text, last_server_seq = parse_chat_message(
            #             hdr + body, session_aes_key, server_pubkey, last_server_seq
            #         )
            #         print("[CHAT_RX] from server (unexpected):", reply_text)
            #     except Exception as e:
            #         print("[CHAT_ERROR] invalid reply from server (expected REPLAY/SIG_FAIL):", e)
            #         break
            #     continue

            client_seq += 1
            wire_msg = build_chat_message(client_seq, session_aes_key, client_privkey, text)
            last_wire_msg = wire_msg
            last_text = text

            # # OPTIONAL: tampering test – flip one bit in the ciphertext on first message
            # if text == "TAMPER":
            #     # wire_msg = [4-byte len][JSON bytes]
            #     length = struct.unpack("!I", wire_msg[:4])[0]
            #     msg_bytes = bytearray(wire_msg[4:4 + length])

            #     # msg_bytes is the JSON; find the "ct" hex string and flip one nibble
            #     # For simplicity, flip a byte at some fixed offset (after the header)
            #     # This will corrupt the ciphertext but leave the signature unchanged.
            #     if len(msg_bytes) > 40:
            #         msg_bytes[40] ^= 0x01  # flip one bit

            #     wire_msg = struct.pack("!I", len(msg_bytes)) + bytes(msg_bytes)
            #     print("[TAMPER] sent tampered ciphertext for SIG_FAIL test")

            conn.sendall(wire_msg)

            # Log outbound message metadata
            import time
            ts = time.time()
            line = f"TX|{client_seq}|{ts}|server|{text}\n"
            transcript.append(line)

            # Receive server reply
            hdr = conn.recv(4)
            if not hdr:
                print("[CHAT] server closed connection")
                break
            (msg_len,) = struct.unpack("!I", hdr)
            body = conn.recv(msg_len)
            if len(body) != msg_len:
                print("[CHAT] incomplete reply from server")
                break

            try:
                reply_text, last_server_seq = parse_chat_message(
                    hdr + body, session_aes_key, server_pubkey, last_server_seq
                )
                print("[CHAT_RX] from server:", reply_text)

                # Log inbound message metadata
                ts = time.time()
                line = f"RX|{last_server_seq}|{ts}|server|{reply_text}\n"
                transcript.append(line)
            except Exception as e:
                print("[CHAT_ERROR] invalid reply from server:", e)
                break
        # end chat loop

        # --- Session Receipt (client side) ---
        from hashlib import sha256

        transcript_bytes = "".join(transcript).encode("utf-8")
        transcript_hash = sha256(transcript_bytes).digest()

        # Sign the transcript hash with client RSA private key
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import padding as asym_padding

        client_receipt_sig = client_privkey.sign(
            transcript_hash,
            asym_padding.PKCS1v15(),
            hashes.SHA256(),
        )

        print("[RECEIPT] client transcript SHA256:", transcript_hash.hex())
        print("[RECEIPT] client signature:", client_receipt_sig.hex())

        with open("client_session_receipt.txt", "w", encoding="utf-8") as f:
            f.write("TRANSCRIPT:\n")
            f.writelines(transcript)
            f.write("\nHASH:" + transcript_hash.hex() + "\n")
            f.write("SIG:" + client_receipt_sig.hex() + "\n")

if __name__ == "__main__":
    main()
    print("Client exited.")
