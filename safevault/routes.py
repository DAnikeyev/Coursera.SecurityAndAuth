"""HTTP routes for SafeVault.

Activity 1-3 endpoints wired together: registration/login (auth), a user
dashboard, an admin-only dashboard (RBAC), and a record search that demonstrates
parameterized queries + output escaping.
"""

from __future__ import annotations

import sqlite3

from flask import Blueprint, current_app, jsonify, request, session

from .auth import AuthenticationError, RegistrationError, authenticate_user, register_user
from .authorization import get_current_user, login_required, role_required
from .db import add_record, search_records_by_title
from .validation import (
    ValidationError,
    escape_html,
    sanitize_input,
    validate_email,
    validate_username,
)

bp = Blueprint("safevault", __name__)


def _conn() -> sqlite3.Connection:
    return current_app.config["DB_CONN"]


def _safe_str(value: str | None) -> str:
    """Convenience: sanitize a free-form string field."""
    return sanitize_input(value or "")


@bp.post("/register")
def register():
    """Register a new user (default role ``user``)."""
    data = request.get_json(silent=True) or {}
    try:
        user_id = register_user(
            _conn(),
            username=data.get("username", ""),
            email=data.get("email", ""),
            password=data.get("password", ""),
        )
    except (ValidationError, RegistrationError) as exc:
        return jsonify(error=str(exc)), 400
    return jsonify(message="User registered.", user_id=user_id), 201


@bp.post("/login")
def login():
    """Authenticate and start a session."""
    data = request.get_json(silent=True) or {}
    username = _safe_str(data.get("username", ""))
    password = data.get("password", "")
    try:
        user = authenticate_user(_conn(), username, password)
    except AuthenticationError as exc:
        return jsonify(error=str(exc)), 401
    # Regenerate to prevent session fixation.
    session.clear()
    session["user_id"] = user["id"]
    return jsonify(message="Logged in.", username=user["username"], role=user["role"])


@bp.post("/logout")
def logout():
    session.clear()
    return jsonify(message="Logged out.")


@bp.get("/dashboard")
@login_required
def dashboard():
    user = get_current_user(_conn())
    return jsonify(username=user["username"], role=user["role"])


@bp.get("/admin")
@role_required("admin")
def admin_dashboard():
    """Admin-only endpoint protected by RBAC."""
    conn = _conn()
    users = conn.execute("SELECT id, username, email, role FROM users").fetchall()
    return jsonify(users=[dict(u) for u in users])


@bp.post("/records")
@login_required
def create_record():
    """Create a record owned by the current user."""
    data = request.get_json(silent=True) or {}
    title = _safe_str(data.get("title", ""))
    content = _safe_str(data.get("content", ""))
    if not title:
        return jsonify(error="Title is required."), 400
    user = get_current_user(_conn())
    record_id = add_record(_conn(), user["id"], title, content)
    return jsonify(message="Record created.", record_id=record_id), 201


@bp.get("/search")
@login_required
def search():
    """Search records by title (parameterized query, escaped output)."""
    term = request.args.get("q", "")
    # Defense in depth: sanitize the search term before it reaches the query.
    term = sanitize_input(term)
    rows = search_records_by_title(_conn(), term)
    # Escape every field on output so stored XSS payloads cannot execute in a
    # browser even if they were persisted.
    results = [
        {
            "id": r["id"],
            "title": escape_html(r["title"]),
            "content": escape_html(r["content"]),
        }
        for r in rows
    ]
    return jsonify(results=results)
