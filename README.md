# SecureChat – Assignment #2 (CS-3002 Information Security, Fall 2025)

This repository contains a **console-based, PKI-enabled Secure Chat System** in **Python**, demonstrating how cryptographic primitives combine to achieve:

**Confidentiality, Integrity, Authenticity, and Non-Repudiation (CIANR)**.

> GitHub repository:  
> https://github.com/aye-shadow/secure-chat 


## 🧩 Overview

The system runs over **plain TCP (no TLS)** and implements all crypto at the **application layer**:

- **PKI** with a Root CA and client/server leaf certificates.
- **X.509 validation**: CA signature, validity window, hostname (CN/SAN).
- **Ephemeral Diffie–Hellman** to derive shared AES-128 keys.
- **AES-128-ECB** with PKCS#7 for registration/login/session-ready messages.
- **AES-128-CBC** with PKCS#7 + RSA signatures for chat messages.
- **MySQL user store** with salted SHA-256 password hashes.
- **Session receipts** (client and server) with signed transcripts for non-repudiation.
- Manual scripts to **generate CA** and **issue client/server certificates**.


## 🏗️ Folder Structure

```
securechat/
├─ app/
│  ├─ client.py              # Client workflow (TCP, cert exchange, DH, login, chat, receipts)
│  ├─ server.py              # Server workflow (TCP, cert validation, DH, login, chat, receipts)
│  ├─ crypto/
│  │  ├─ aes.py              # AES-128(ECB)+PKCS#7 helpers
│  │  ├─ dh.py               # DH helpers + AES key derivation
│  │  ├─ pki.py              # X.509 validation (CA signature, validity, CN/SAN)
│  │  ├─ chat.py             # Signed & encrypted chat message format (CBC + RSA)
│  │  └─ sign.py             # RSA sign/verify (not used directly in current code)
│  ├─ common/
│  │  ├─ protocol.py         # Pydantic models (not used in the final flow)
│  │  └─ utils.py            # Helpers for base64, SHA-256, and framed I/O
│  └─ storage/
│     ├─ db.py               # MySQL user store (salted SHA-256 passwords)
│     └─ transcript.py       # (not used – session receipts handled in client/server)
├─ certs/
│  ├─ ca/                    # Root CA key/cert
│  ├─ client/                # Client key/cert
│  ├─ server/                # Server key/cert
│  ├─ fake_ca/               # Fake CA (for BAD_CERT tests)
│  └─ fake_server/           # Fake server cert/key (for BAD_CERT tests)
├─ scripts/
│  ├─ gen_ca.py              # Create Root CA
│  └─ gen_cert.py            # Issue client/server certs signed by Root CA
├─ tests/
│  └─ manual/
│     ├─ NOTES.md            # Manual testing checklist
│     └─ repu_veri.py        # Offline SessionReceipt verification helper
├─ server_session_receipt.txt
├─ client_session_receipt.txt
├─ requirements.txt
└─ README.md
```


## ⚙️ Configuration

### 1. Python Environment

```bash
python -m venv .venv
# Linux/macOS
source .venv/bin/activate
# Windows (PowerShell)
.venv\Scripts\Activate.ps1

pip install -r requirements.txt
```

### 2. MySQL Database

The app uses MySQL with the following default configuration (see [`app.storage.db`](app/storage/db.py)):

- Host: `127.0.0.1`
- Port: `3306`
- User: `scuser`
- Password: `scpass`
- Database: `securechat`

You can override via environment variables:

- `DB_HOST`
- `DB_PORT`
- `DB_USER`
- `DB_PASSWORD`
- `DB_NAME`

#### Recommended: Docker-based MySQL

```bash
docker run -d --name securechat-db \
  -e MYSQL_ROOT_PASSWORD=rootpass \
  -e MYSQL_DATABASE=securechat \
  -e MYSQL_USER=scuser \
  -e MYSQL_PASSWORD=scpass \
  -p 3306:3306 mysql:8
```

Initialize schema:

```bash
python -m app.storage.db --init
```


### 3. Certificates

If you don’t already have the certs generated, use the provided scripts:

```bash
# Root CA
python scripts/gen_ca.py --name "FAST-NU Root CA"

# Server cert
python scripts/gen_cert.py --cn server.local --out certs/server

# Client cert
python scripts/gen_cert.py --cn client.local --out certs/client
```

The runtime code expects:

- CA: `certs/ca/ca_cert.pem`
- Server cert/key: `certs/server/cert.pem`, `certs/server/key.pem`
- Client cert/key: `certs/client/cert.pem`, `certs/client/key.pem`


## 🚀 Execution Steps

### 1. Start the Server

```bash
python -m app.server
```

Server flow (`app.server`):

1. Waits for TCP connections on `0.0.0.0:9000`.
2. Receives client certificate and verifies it:
   - Signed by Root CA.
   - Within validity interval.
   - Hostname matches `client.local`.
3. Sends its own server certificate.
4. Runs DH to derive an **AES-128 key** (`aes_key`).
5. Receives and decrypts **registration** payload, creates DB user.
6. Receives and decrypts **login** payload, verifies password.
7. If login OK:
   - Runs a second DH to derive a **session AES key** (`session_aes_key`).
   - Sends encrypted `"session ready"` message.
   - Enters encrypted **chat loop** with signed messages.
   - On disconnect, writes `server_session_receipt.txt` with transcript, SHA256 hash, and RSA signature.

### 2. Start the Client

In another terminal:

```bash
python -m app.client
```

Client flow (`app.client`):

1. Connects to `127.0.0.1:9000`.
2. Loads Root CA + client cert/key.
3. Sends client certificate.
4. Receives and validates server certificate (signed-by CA, hostname `server.local`).
5. Runs DH to derive **AES key** (`aes_key`).
6. Sends AES-128-ECB encrypted **registration** JSON:
   - `{"type": "register", "email": "...", "username": "...", "password": "..."}` (hardcoded).
7. Sends AES-128-ECB encrypted **login** JSON for the same username/password.
8. Receives AES-128-ECB encrypted login response (`{"status": "ok" | "error"}`).
9. If status is `ok`:
   - Runs second DH to derive **session AES key** (`session_aes_key`).
   - Receives AES-encrypted `"session ready"` message.
   - Enters interactive **chat loop**, sending signed & encrypted messages.

10. On exit, writes `client_session_receipt.txt` with transcript, SHA256 hash, and RSA signature.

> Note: registration/login credentials are currently **hardcoded** in `app.client`:
> ```python
> email = "alice14@example.com"
> username = "alice14"
> password = "supersecret"
> ```


## 💬 Chat Message Format

Implemented in [`app.crypto.chat`](app/crypto/chat.py).

Each chat message is framed as:

- **Outer framing**:  
  `[4-byte big-endian length][JSON bytes]`

- **JSON structure**:
  ```json
  {
    "seqno": <int>,     // monotonically increasing
    "ts": <float>,      // timestamp (seconds)
    "iv": "<hex>",      // 16-byte IV for AES-CBC
    "ct": "<hex>",      // AES-128-CBC ciphertext
    "sig": "<hex>"      // RSA PKCS#1 v1.5 signature over SHA256(seqno || ts || ct)
  }
  ```

Encryption/signing:

- AES mode: **CBC**, key `session_aes_key` (16 bytes).
- Padding: **PKCS#7**.
- Signature: RSA PKCS#1 v1.5 with SHA-256 over:
  `seqno || ts || ct` (packed via `struct.pack`).

Verification:

- `parse_chat_message(...)`:
  - Checks message length framing.
  - Enforces **strictly increasing `seqno`** (replay protection).
  - Recomputes hash and verifies RSA signature using peer’s public key.
  - Decrypts AES-CBC and unpads to get plaintext string.


## 📥 Sample Input / Output

### 1. Registration & Login (over AES-ECB)

From client side (plaintext before encryption):

```json
{
  "type": "register",
  "email": "alice14@example.com",
  "username": "alice14",
  "password": "supersecret"
}
```

```json
{
  "type": "login",
  "username": "alice14",
  "password": "supersecret"
}
```

Server plaintext response (before encryption):

```json
{"status": "ok"}
```

or

```json
{"status": "error", "reason": "invalid_credentials"}
```

On the wire, all of these are AES-128-ECB encrypted and framed as:

- `[4-byte big-endian length][ciphertext bytes]`.

### 2. Chat (interactive)

Example console session:

**Client:**

```text
> ugh i hate this bruh
[CHAT_RX] from server: Echo: ugh i hate this bruh
> sigh
[CHAT_RX] from server: Echo: sigh
> 
Client exited.
```

**Server:**

```text
[CHAT_RX] from ('127.0.0.1', 12345): 'ugh i hate this bruh'
[CHAT_RX] from ('127.0.0.1', 12345): 'sigh'
[CHAT] client ('127.0.0.1', 12345) disconnected
Server exited.
```


## 🧾 Session Receipts & Offline Verification

Both client and server write receipts at the end of a chat session:

- Client: `client_session_receipt.txt`
- Server: `server_session_receipt.txt`

Format:

```text
TRANSCRIPT:
TX|1|1763327230.0977857|server|ugh i hate this bruh
RX|1|1763327230.0992265|server|Echo: ugh i hate this bruh
...

HASH:<hex SHA256 of transcript text>
SIG:<hex RSA signature over HASH>
```

You can verify a receipt offline using [`tests/manual/repu_veri.py`](tests/manual/repu_veri.py):

```bash
# Verify server-side receipt
python tests/manual/repu_veri.py
# (edit RECEIPT_PATH and CERT_PATH inside the script if needed)
```


## 🔬 Manual Test Evidence

Use [`tests/manual/NOTES.md`](tests/manual/NOTES.md) as a checklist.

- **Wireshark**: capture traffic on port 9000 and confirm that:
  - Registration/login/chat payloads are encrypted (no plaintext credentials/messages).
- **BAD_CERT**:
  - Use `certs/fake_ca` or `certs/fake_server` with the real CA to trigger `BadCertificate` paths.
- **SIG_FAIL (Tamper test)**:
  - In `app.client`, there is commented-out code to flip a bit in the ciphertext before sending.
  - Enable it to show that the server logs `[SIG_FAIL]` and drops the message.
- **REPLAY**:
  - In `app.client`, there is commented-out `REPLAY` code to resend an old message with the same `seqno`.
  - Enable it and observe that `parse_chat_message` rejects non-increasing `seqno`.
- **Non-repudiation**:
  - Use `repu_veri.py` to validate the RSA signature on the session receipt hash.


## 🚫 Important Rules (per assignment)

- Do **not** use TLS/SSL or any secure-channel abstraction  
  (e.g., `ssl`, HTTPS, WSS, OpenSSL socket wrappers).  
  All crypto operations occur **explicitly** at the application layer.
- You are **not required** to implement AES, RSA, or DH math; use existing libraries.
- Do **not commit secrets** (certs, private keys, salts, `.env` values) to public repos.
- Commits should reflect progressive development (at least **10 meaningful commits**).