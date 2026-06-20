"""Authentication for SafeVault.

Activity 2 - Step 2: authentication with secure password hashing (bcrypt).

Passwords are never stored or compared in plaintext. We hash with **bcrypt**
(salted, adaptive cost) on registration and verify by re-hashing the supplied
candidate against the stored hash on login. Even if the database is exfiltrated,
an attacker cannot recover plaintext passwords.
"""

from __future__ import annotations

import sqlite3

import bcrypt

from .db import create_user, get_user_by_username
from .validation import validate_email, validate_password, validate_username

# bcrypt truncates passwords at 72 bytes; round it to a sane work factor.
_BCRYPT_ROUNDS = 12


class AuthenticationError(Exception):
    """Raised when login fails."""


class RegistrationError(Exception):
    """Raised when registration fails (e.g. duplicate username)."""


def hash_password(password: str) -> str:
    """Return a bcrypt hash of *password* (encoded as a utf-8 str)."""
    # bcrypt works on bytes; we encode and decode at the boundary.
    salt = bcrypt.gensalt(rounds=_BCRYPT_ROUNDS)
    hashed = bcrypt.hashpw(password.encode("utf-8"), salt)
    return hashed.decode("utf-8")


def verify_password(password: str, password_hash: str) -> bool:
    """Return True if *password* matches the stored *password_hash*.

    Uses :func:`bcrypt.checkpw` which runs in constant time relative to the
    hash, mitigating timing-based user enumeration.
    """
    if not password_hash:
        return False
    try:
        return bcrypt.checkpw(password.encode("utf-8"), password_hash.encode("utf-8"))
    except ValueError:
        # Malformed hash -> treat as no match.
        return False


def register_user(
    conn: sqlite3.Connection,
    username: str,
    email: str,
    password: str,
    role: str = "user",
) -> int:
    """Validate inputs, hash the password, and persist a new user.

    Returns the new user id. Raises :class:`RegistrationError` on conflict.
    """
    username = validate_username(username)
    email = validate_email(email)
    validate_password(password)

    if get_user_by_username(conn, username) is not None:
        raise RegistrationError("Username already exists.")

    try:
        return create_user(conn, username, email, hash_password(password), role)
    except sqlite3.IntegrityError as exc:
        # UNIQUE constraint violation (email collision, race, etc.).
        raise RegistrationError("Username or email already exists.") from exc


def authenticate_user(
    conn: sqlite3.Connection,
    username: str,
    password: str,
) -> sqlite3.Row:
    """Verify credentials and return the user row on success.

    Raises :class:`AuthenticationError` if the username is unknown or the
    password does not match. We use the same error for both cases so that login
    responses do not reveal which one was wrong (anti-enumeration).
    """
    user = get_user_by_username(conn, username)
    # Always run a hash comparison to keep timing uniform whether or not the
    # user exists.
    valid = verify_password(password, user["password_hash"]) if user else False
    if not user or not valid:
        raise AuthenticationError("Invalid username or password.")
    return user
