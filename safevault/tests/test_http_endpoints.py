"""HTTP-level security tests: SQL-injection / XSS via the API surface.

Confirms the running Flask app neutralizes payloads sent through register,
login, and search endpoints (Activity 1/3, Step 4 - end-to-end).
"""

from __future__ import annotations

import pytest

from safevault.auth import register_user
from safevault.db import add_record


@pytest.fixture()
def seeded_client(app):
    conn = app.config["DB_CONN"]
    register_user(conn, "alice", "alice@example.com", "Secret123", role="user")
    # A record whose title is an XSS payload (simulating stored XSS).
    add_record(conn, 1, "<script>alert(1)</script>", "<img src=x onerror=alert(2)>")
    client = app.test_client()
    client.post("/login", json={"username": "alice", "password": "Secret123"})
    return client


@pytest.mark.parametrize(
    "payload",
    ["alice", "alice'--", "' OR '1'='1", "admin'/*", "'; DROP TABLE users; --"],
)
def test_login_endpoint_resists_injection(app, payload):
    client = app.test_client()
    # Register a real user first so the DB is not empty.
    client.post(
        "/register",
        json={"username": "alice", "email": "alice@example.com", "password": "Secret123"},
    )
    res = client.post("/login", json={"username": payload, "password": "anything"})
    # Must be rejected (401). Critically, must NOT be 200 (logged in).
    assert res.status_code == 401


def test_search_escapes_stored_xss(seeded_client):
    res = seeded_client.get("/search?q=script")
    body = res.get_json()
    assert res.status_code == 200
    # The payload title must come back escaped, not raw. Attribute names may
    # appear as inert text, but no live tag may survive.
    for r in body["results"]:
        assert "<script>" not in r["title"]
        assert "<img" not in r["content"]
        assert "&lt;script&gt;" in r["title"]
        assert "&lt;img" in r["content"]


def test_register_rejects_invalid_username(app):
    client = app.test_client()
    res = client.post(
        "/register",
        json={"username": "a';--", "email": "x@y.com", "password": "Secret123"},
    )
    assert res.status_code == 400
