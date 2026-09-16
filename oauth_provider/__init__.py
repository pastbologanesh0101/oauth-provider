"""Custom OAuth Provider.

A minimal, from-scratch implementation of the OAuth 2.0 Authorization
Code flow, built with Flask and SQLite.
"""
import os
import sqlite3

from flask import Flask

from .db import init_db, seed_demo_data
from .views import bp

__all__ = ["create_app"]


def create_app(testing=False, db_path=None):
    """Application factory.

    Args:
        testing: When True, configures the app for tests and defaults
            to an in-memory SQLite database.
        db_path: Optional explicit sqlite path/URI. Defaults to
            ':memory:' when testing, otherwise a file next to this
            package.
    """
    app = Flask(__name__)
    app.config["TESTING"] = bool(testing)

    if db_path is None:
        if testing:
            db_path = ":memory:"
        else:
            db_path = os.path.join(
                os.path.dirname(os.path.abspath(__file__)), "..", "oauth.db"
            )

    conn = sqlite3.connect(db_path, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    init_db(conn)
    seed_demo_data(conn)

    app.extensions["db_conn"] = conn

    app.register_blueprint(bp)

    return app
