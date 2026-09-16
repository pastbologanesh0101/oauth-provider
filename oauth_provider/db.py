"""SQLite schema and connection helpers."""
from flask import current_app

SCHEMA = """
CREATE TABLE IF NOT EXISTS clients (
    client_id TEXT PRIMARY KEY,
    client_secret TEXT NOT NULL,
    redirect_uri TEXT NOT NULL,
    name TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS users (
    username TEXT PRIMARY KEY,
    password TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS auth_codes (
    code TEXT PRIMARY KEY,
    client_id TEXT NOT NULL,
    redirect_uri TEXT NOT NULL,
    username TEXT NOT NULL,
    expires_at REAL NOT NULL,
    used INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS tokens (
    access_token TEXT PRIMARY KEY,
    client_id TEXT NOT NULL,
    username TEXT NOT NULL,
    expires_at REAL NOT NULL
);
"""


def init_db(conn):
    """Create tables if they do not already exist."""
    conn.executescript(SCHEMA)
    conn.commit()


def seed_demo_data(conn):
    """Register a demo client app and a demo user for the walkthrough.

    Safe to call repeatedly (uses INSERT OR IGNORE).
    """
    conn.execute(
        "INSERT OR IGNORE INTO clients (client_id, client_secret, redirect_uri, name) "
        "VALUES (?, ?, ?, ?)",
        ("demo-client-id", "demo-client-secret", "http://localhost:9000/callback", "Demo Client App"),
    )
    conn.execute(
        "INSERT OR IGNORE INTO users (username, password) VALUES (?, ?)",
        ("alice", "password123"),
    )
    conn.commit()


def get_db():
    """Return the sqlite3 connection attached to the current app."""
    return current_app.extensions["db_conn"]
