from __future__ import annotations
"""Pydantic models: hello, server_hello, register, login, dh_client, dh_server, msg, receipt."""

from pydantic import BaseModel


class Hello(BaseModel):
    # client -> server: supports versioning, etc.
    proto: str = "SecureChat/1"
    # client's ephemeral DH public key (PEM, base64‑encoded)
    dh_pub_b64: str


class ServerHello(BaseModel):
    # server -> client: ack + its ephemeral DH public key
    proto: str = "SecureChat/1"
    dh_pub_b64: str


class Register(BaseModel):
    # AES‑encrypted JSON {email, username, password}, base64‑encoded
    ct_b64: str


class Login(BaseModel):
    # AES‑encrypted JSON {username, password}, base64‑encoded
    ct_b64: str