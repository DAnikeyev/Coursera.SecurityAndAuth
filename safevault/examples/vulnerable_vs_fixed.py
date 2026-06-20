"""Vulnerable-vs-fixed reference (Activity 3: debug & resolve vulnerabilities).

This module documents the specific insecure patterns that were identified during
the security review of the SafeVault codebase and shows the corrected version
used throughout the application. The functions here are **intentionally
insecure** on the ``_vulnerable_*`` side - they exist only to make the diff
between the buggy and fixed code explicit and to be exercised by the test suite
in ``tests/test_debug_fixes.py``.

DO NOT use the ``_vulnerable_*`` functions in production code.
"""

from __future__ import annotations

import sqlite3


# --------------------------------------------------------------------------- #
# Issue 1: SQL injection via string concatenation
# --------------------------------------------------------------------------- #
def _vulnerable_get_user(conn: sqlite3.Connection, username: str) -> sqlite3.Row | None:
    """INSECURE: builds SQL with an f-string.

    An attacker supplying ``admin' --`` rewrites the query to log in as admin
    without a password. See ``tests/test_debug_fixes.py`` for the exploit.
    """
    sql = f"SELECT * FROM users WHERE username = '{username}'"  # noqa: S608
    return conn.execute(sql).fetchone()


def secure_get_user(conn: sqlite3.Connection, username: str) -> sqlite3.Row | None:
    """FIXED: parameterized query.

    ``username`` is bound as a value, so ``admin' --`` is treated as a literal
    string and matches no row.
    """
    return conn.execute(
        "SELECT * FROM users WHERE username = ?", (username,)
    ).fetchone()


# --------------------------------------------------------------------------- #
# Issue 2: Stored XSS via unescaped output
# --------------------------------------------------------------------------- #
def _vulnerable_render(record_title: str) -> str:
    """INSECURE: returns user content without escaping.

    A title such as ``<script>alert('xss')</script>`` is rendered verbatim and
    executes in any browser that displays the value.
    """
    return f"<h1>{record_title}</h1>"


def secure_render(record_title: str) -> str:
    """FIXED: HTML-escape user content before interpolation into a template."""
    from html import escape

    return f"<h1>{escape(record_title)}</h1>"


# --------------------------------------------------------------------------- #
# Issue 3: Login error message enables username enumeration
# --------------------------------------------------------------------------- #
def _vulnerable_login_error(user_exists: bool) -> str:
    """INSECURE: distinct messages reveal whether a username is registered."""
    return "No such user." if not user_exists else "Wrong password."


def secure_login_error() -> str:
    """FIXED: identical message regardless of which check failed."""
    return "Invalid username or password."
