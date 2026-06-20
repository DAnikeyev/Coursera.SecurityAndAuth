"""Database access layer for SafeVault.

Activity 1 - Step 3: parameterized queries to prevent SQL injection.

Every query in this module uses **parameterized statements** (``?`` placeholders
bound by the sqlite3 driver). User data is *never* interpolated into the SQL
string via f-strings, ``%`` formatting, or concatenation. Even if an attacker
supplies ``' OR '1'='1`` as a username, it is treated as a literal string value
and cannot alter the query structure.
"""

from __future__ import annotations

import sqlite3
from contextlib import contextmanager
from typing import Any, Iterator, Sequence

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    username      TEXT    NOT NULL UNIQUE,
    email         TEXT    NOT NULL UNIQUE,
    password_hash TEXT    NOT NULL,
    role          TEXT    NOT NULL DEFAULT 'user'
);

CREATE TABLE IF NOT EXISTS records (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    owner_id INTEGER NOT NULL,
    title    TEXT    NOT NULL,
    content  TEXT    NOT NULL,
    FOREIGN KEY (owner_id) REFERENCES users (id)
);
"""


def get_connection(db_path: str = ":memory:") -> sqlite3.Connection:
    """Return a sqlite3 connection.

    ``row_factory`` is set to :class:`sqlite3.Row` so results behave like dicts.
    """
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    # Enforce foreign keys (off by default in SQLite).
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db(conn: sqlite3.Connection) -> None:
    """Create tables if they do not already exist."""
    conn.executescript(SCHEMA)
    conn.commit()


@contextmanager
def transaction(conn: sqlite3.Connection) -> Iterator[sqlite3.Connection]:
    """Context manager that commits on success and rolls back on error."""
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise


def execute_query(
    conn: sqlite3.Connection,
    sql: str,
    params: Sequence[Any] = (),
) -> sqlite3.Cursor:
    """Execute a *parameterized* SQL statement.

    The ``sql`` string must use ``?`` placeholders; values are supplied via
    ``params`` and bound safely by the driver. This is the single safe way to
    run user-influenced SQL in this codebase.

    Raises:
        TypeError: if ``params`` is not a sequence (guards against accidental
            unsafe calls).
    """
    if not isinstance(params, (tuple, list)):
        raise TypeError("params must be a tuple or list of values")
    return conn.execute(sql, params)


def create_user(
    conn: sqlite3.Connection,
    username: str,
    email: str,
    password_hash: str,
    role: str = "user",
) -> int:
    """Insert a new user and return the new row id.

    SECURE: all four values are bound as parameters.
    """
    with transaction(conn):
        cur = execute_query(
            conn,
            "INSERT INTO users (username, email, password_hash, role) "
            "VALUES (?, ?, ?, ?)",
            (username, email, password_hash, role),
        )
    return cur.lastrowid


def get_user_by_username(conn: sqlite3.Connection, username: str) -> sqlite3.Row | None:
    """Return a user row by username, or ``None``.

    SECURE: ``username`` is bound as a parameter. A value such as
    ``admin' --`` is treated as a literal and simply matches nothing.
    """
    return execute_query(
        conn,
        "SELECT id, username, email, password_hash, role FROM users WHERE username = ?",
        (username,),
    ).fetchone()


def get_user_by_id(conn: sqlite3.Connection, user_id: int) -> sqlite3.Row | None:
    """Return a user row by primary key, or ``None``."""
    return execute_query(
        conn,
        "SELECT id, username, email, role FROM users WHERE id = ?",
        (user_id,),
    ).fetchone()


def search_records_by_title(conn: sqlite3.Connection, title: str) -> list[sqlite3.Row]:
    """Search records by title.

    SECURE: ``title`` is bound as a parameter. The classic injection
    ``anything' OR '1'='1`` cannot return every row - it becomes a literal
    substring comparison that matches nothing.
    """
    return execute_query(
        conn,
        "SELECT id, owner_id, title, content FROM records WHERE title LIKE ?",
        (f"%{title}%",),
    ).fetchall()


def add_record(
    conn: sqlite3.Connection,
    owner_id: int,
    title: str,
    content: str,
) -> int:
    """Insert a record owned by *owner_id*."""
    with transaction(conn):
        cur = execute_query(
            conn,
            "INSERT INTO records (owner_id, title, content) VALUES (?, ?, ?)",
            (owner_id, title, content),
        )
    return cur.lastrowid
