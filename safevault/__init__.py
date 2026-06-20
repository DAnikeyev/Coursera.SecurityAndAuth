"""SafeVault application factory.

Usage::

    from safevault import create_app
    app = create_app()
    app.run(debug=True)
"""

from __future__ import annotations

import sqlite3
from typing import Optional

from flask import Flask

from .db import get_connection, init_db


def create_app(db_path: str = ":memory:", secret_key: str = "dev-secret-change-me") -> Flask:
    """Create and configure the SafeVault Flask app.

    Args:
        db_path: Path to the SQLite database file. Defaults to an in-memory
            database (ideal for tests).
        secret_key: Flask secret used to sign sessions. Override in production.
    """
    app = Flask(__name__)
    app.config["SECRET_KEY"] = secret_key
    app.config["TESTING"] = False

    conn: sqlite3.Connection = get_connection(db_path)
    init_db(conn)
    app.config["DB_CONN"] = conn

    from .routes import bp

    app.register_blueprint(bp)
    return app


def get_or_create_conn(app: Flask) -> sqlite3.Connection:
    return app.config["DB_CONN"]
