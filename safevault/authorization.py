"""Role-based access control (RBAC) for SafeVault.

Activity 2 - Step 3: restrict access to features based on user roles.

Roles are stored on each user row (``user`` or ``admin``). The
:func:`role_required` decorator protects Flask routes so that, for example, the
Admin Dashboard is reachable only by users whose role is ``admin``.
"""

from __future__ import annotations

import sqlite3
from functools import wraps
from typing import Callable, Iterable

from flask import current_app, jsonify, session

from .db import get_user_by_id

# The roles the application recognises, in order of privilege.
ROLES = ("user", "admin")


def get_current_user(conn: sqlite3.Connection) -> sqlite3.Row | None:
    """Return the currently logged-in user row, or ``None``.

    Looks up the user id stored in the Flask ``session`` on each request so that
    revoking a role takes effect immediately rather than waiting for the session
    to expire.
    """
    user_id = session.get("user_id")
    if user_id is None:
        return None
    return get_user_by_id(conn, user_id)


def user_has_role(user: sqlite3.Row | None, allowed_roles: Iterable[str]) -> bool:
    """Return True if *user* is non-null and their role is in *allowed_roles*."""
    if user is None:
        return False
    return user["role"] in set(allowed_roles)


def role_required(*allowed_roles: str) -> Callable:
    """Decorator that restricts a Flask view to the given roles.

    Usage::

        @app.route("/admin")
        @role_required("admin")
        def admin_dashboard():
            ...

    Unauthenticated requests get a 401; authenticated-but-unauthorized requests
    get a 403.
    """
    required = set(allowed_roles)

    def decorator(view: Callable) -> Callable:
        @wraps(view)
        def wrapped(*args, **kwargs):
            conn = current_app.config["DB_CONN"]
            user = get_current_user(conn)
            if user is None:
                return jsonify(error="Authentication required."), 401
            if not user_has_role(user, required):
                return jsonify(error="Forbidden: insufficient role."), 403
            return view(*args, **kwargs)

        return wrapped

    return decorator


def login_required(view: Callable) -> Callable:
    """Decorator that only requires an authenticated user (any role)."""
    @wraps(view)
    def wrapped(*args, **kwargs):
        conn = current_app.config["DB_CONN"]
        if get_current_user(conn) is None:
            return jsonify(error="Authentication required."), 401
        return view(*args, **kwargs)

    return wrapped
