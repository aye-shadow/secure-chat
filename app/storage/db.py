from __future__ import annotations
"""MySQL users table + salted hashing (no chat storage)."""

import argparse
import os
from dataclasses import dataclass

import pymysql

from app.common.utils import sha256_hex


@dataclass
class DBConfig:
    host: str = os.getenv("DB_HOST", "127.0.0.1")
    port: int = int(os.getenv("DB_PORT", "3306"))
    user: str = os.getenv("DB_USER", "scuser")
    password: str = os.getenv("DB_PASSWORD", "scpass")
    db: str = os.getenv("DB_NAME", "securechat")


def get_conn(cfg: DBConfig | None = None):
    if cfg is None:
        cfg = DBConfig()
    return pymysql.connect(
        host=cfg.host,
        port=cfg.port,
        user=cfg.user,
        password=cfg.password,
        db=cfg.db,
        autocommit=True,
    )


def init_schema():
    conn = get_conn()
    with conn, conn.cursor() as cur:
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INT AUTO_INCREMENT PRIMARY KEY,
                email VARCHAR(255) NOT NULL UNIQUE,
                username VARCHAR(64) NOT NULL UNIQUE,
                salt BINARY(16) NOT NULL,
                pwd_hash CHAR(64) NOT NULL
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
            """
        )


def create_user(email: str, username: str, password: str):
    import os

    salt = os.urandom(16)
    pwd_hash = sha256_hex(salt + password.encode("utf-8"))

    conn = get_conn()
    with conn, conn.cursor() as cur:
        cur.execute(
            "INSERT INTO users (email, username, salt, pwd_hash) VALUES (%s, %s, %s, %s)",
            (email, username, salt, pwd_hash),
        )


def verify_user(username: str, password: str) -> bool:
    conn = get_conn()
    with conn, conn.cursor() as cur:
        cur.execute(
            "SELECT salt, pwd_hash FROM users WHERE username = %s",
            (username,),
        )
        row = cur.fetchone()
        if not row:
            return False
        salt, stored_hash = row
        candidate = sha256_hex(salt + password.encode("utf-8"))
        return candidate == stored_hash


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--init", action="store_true", help="initialize DB schema")
    args = parser.parse_args()
    if args.init:
        init_schema()
        print("Initialized DB schema.")


if __name__ == "__main__":
    main()