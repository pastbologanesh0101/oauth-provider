"""Data access helpers for clients, users, authorization codes and tokens."""
import secrets
import time

from .db import get_db

AUTH_CODE_TTL = 60          # seconds an authorization code stays valid
ACCESS_TOKEN_TTL = 3600     # seconds an access token stays valid


def get_client(client_id):
    """Look up a registered client by client_id, or None."""
    db = get_db()
    return db.execute(
        "SELECT * FROM clients WHERE client_id = ?", (client_id,)
    ).fetchone()


def verify_user(username, password):
    """Check demo user credentials (plaintext, for demo purposes only)."""
    db = get_db()
    row = db.execute(
        "SELECT * FROM users WHERE username = ?", (username,)
    ).fetchone()
    return row is not None and row["password"] == password


def create_auth_code(client_id, redirect_uri, username, ttl_seconds=AUTH_CODE_TTL):
    """Issue a new authorization code bound to a client_id + redirect_uri."""
    db = get_db()
    code = secrets.token_urlsafe(24)
    expires_at = time.time() + ttl_seconds
    db.execute(
        "INSERT INTO auth_codes (code, client_id, redirect_uri, username, expires_at, used) "
        "VALUES (?, ?, ?, ?, ?, 0)",
        (code, client_id, redirect_uri, username, expires_at),
    )
    db.commit()
    return code


def get_auth_code(code):
    db = get_db()
    return db.execute(
        "SELECT * FROM auth_codes WHERE code = ?", (code,)
    ).fetchone()


def mark_code_used(code):
    db = get_db()
    db.execute("UPDATE auth_codes SET used = 1 WHERE code = ?", (code,))
    db.commit()


def create_access_token(client_id, username, ttl_seconds=ACCESS_TOKEN_TTL):
    """Issue a new bearer access token for a client_id + username."""
    db = get_db()
    token = secrets.token_urlsafe(32)
    expires_at = time.time() + ttl_seconds
    db.execute(
        "INSERT INTO tokens (access_token, client_id, username, expires_at) VALUES (?, ?, ?, ?)",
        (token, client_id, username, expires_at),
    )
    db.commit()
    return token, expires_at


def get_token(access_token):
    db = get_db()
    return db.execute(
        "SELECT * FROM tokens WHERE access_token = ?", (access_token,)
    ).fetchone()
