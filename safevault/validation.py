"""Input validation and sanitization for SafeVault.

Activity 1 - Step 2: secure code for input validation.

These helpers defend against two classes of attacks:

* **SQL injection** - by rejecting / stripping characters that could break out
  of a SQL string literal. Note: the *primary* defense against SQL injection is
  the use of parameterized queries in :mod:`safevault.db`; input validation is a
  defense-in-depth layer, not a replacement.
* **Cross-site scripting (XSS)** - by escaping HTML metacharacters so that any
  user-supplied content is rendered as inert text rather than executable HTML.
"""

from __future__ import annotations

import re
from html import escape

# Tokens that have no legitimate place in usernames / emails and that are
# commonly used to mount SQL-injection or template-injection attacks. We strip
# them rather than reject the whole input so that benign values are preserved.
# Single metacharacters are matched as a character class; multi-char comment /
# SQL sequences are matched separately to avoid regex character-range issues.
_DANGEROUS_SQL_CHARS = re.compile(r"['\";\\#]|--|/\*|\*/|@@")

# A conservative username policy: 3-32 word characters.
_USERNAME_RE = re.compile(r"^[A-Za-z0-9_]{3,32}$")

# Reasonably strict email pattern (good enough for input validation; real
# verification still happens via a confirmation flow out of scope here).
_EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}$")


class ValidationError(ValueError):
    """Raised when user input fails validation."""


def sanitize_input(value: str) -> str:
    """Return *value* with malicious characters and surrounding whitespace removed.

    This is a defense-in-depth measure. It strips:

    * leading / trailing whitespace,
    * SQL metacharacters (quotes, semicolons, comments, etc.),
    * control / non-printable characters.

    It does **not** guarantee safety on its own - always combine with
    parameterized queries (:func:`safevault.db.execute_query`) and output
    escaping (:func:`escape_html`).
    """
    if value is None:
        return ""
    if not isinstance(value, str):
        value = str(value)
    # Normalize and trim.
    value = value.strip()
    # Remove SQL-injection helpers.
    value = _DANGEROUS_SQL_CHARS.sub("", value)
    # Drop control characters (e.g. null bytes used to truncate strings).
    value = "".join(ch for ch in value if ch == "\t" or ch == "\n" or ch >= " ")
    return value.strip()


def escape_html(value: str) -> str:
    """Escape HTML metacharacters to prevent reflected/stored XSS.

    Escapes ``&``, ``<``, ``>``, ``"`` and ``'`` so that a payload such as
    ``<script>alert(1)</script>`` becomes inert text.
    """
    if value is None:
        return ""
    return escape(str(value), quote=True)


def validate_username(username: str) -> str:
    """Validate and return a clean username, or raise :class:`ValidationError`."""
    cleaned = sanitize_input(username)
    if not _USERNAME_RE.fullmatch(cleaned):
        raise ValidationError(
            "Username must be 3-32 characters and contain only letters, "
            "digits, or underscores."
        )
    return cleaned


def validate_email(email: str) -> str:
    """Validate and return a clean email, or raise :class:`ValidationError`."""
    cleaned = sanitize_input(email)
    if not _EMAIL_RE.fullmatch(cleaned):
        raise ValidationError("A valid email address is required.")
    return cleaned.lower()


def validate_password(password: str) -> str:
    """Enforce a minimal password policy.

    Passwords are *not* sanitized - users are allowed (encouraged) to use
    special characters. We only enforce length/complexity. The value is safe to
    store because it is always passed through a parameterized query and only
    ever stored as a bcrypt hash.
    """
    if not isinstance(password, str) or len(password) < 8:
        raise ValidationError("Password must be at least 8 characters long.")
    if not any(ch.isupper() for ch in password):
        raise ValidationError("Password must contain an uppercase letter.")
    if not any(ch.islower() for ch in password):
        raise ValidationError("Password must contain a lowercase letter.")
    if not any(ch.isdigit() for ch in password):
        raise ValidationError("Password must contain a digit.")
    return password


def is_safe_search_term(term: str) -> bool:
    """Return True if *term* is free of obvious SQL-injection/XSS payloads.

    Used as a fast pre-check on free-form search boxes. The real protection is
    still the parameterized query downstream.
    """
    if term is None:
        return False
    lowered = term.lower()
    signatures = (
        "select ", "insert ", "update ", "delete ", "drop ", "union ",
        "or 1=1", "or '1'='1", "--", ";", "<script", "onerror=", "onload=",
        "javascript:",
    )
    return not any(sig in lowered for sig in signatures)
