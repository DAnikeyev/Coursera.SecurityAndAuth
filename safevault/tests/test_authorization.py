"""Authorization / RBAC tests (Activity 2, Step 4).

Drives the Flask endpoints via the test client to confirm role-based access
control: anonymous users are rejected, regular users cannot reach admin
endpoints, and admins can.
"""

from __future__ import annotations

import pytest

from safevault.auth import register_user


@pytest.fixture()
def seeded_app(app):
    conn = app.config["DB_CONN"]
    register_user(conn, "alice", "alice@example.com", "Secret123", role="user")
    register_user(conn, "admin", "admin@example.com", "Admin123!", role="admin")
    return app


def _login(client, username, password):
    return client.post("/login", json={"username": username, "password": password})


class TestUnauthenticatedAccess:
    def test_dashboard_requires_login(self, client):
        res = client.get("/dashboard")
        assert res.status_code == 401

    def test_admin_requires_login(self, client):
        res = client.get("/admin")
        assert res.status_code == 401


class TestRegularUserAccess:
    def test_user_can_reach_dashboard(self, seeded_app):
        client = seeded_app.test_client()
        _login(client, "alice", "Secret123")
        res = client.get("/dashboard")
        assert res.status_code == 200
        assert res.get_json()["role"] == "user"

    def test_user_cannot_reach_admin(self, seeded_app):
        client = seeded_app.test_client()
        _login(client, "alice", "Secret123")
        res = client.get("/admin")
        assert res.status_code == 403


class TestAdminAccess:
    def test_admin_can_reach_admin(self, seeded_app):
        client = seeded_app.test_client()
        _login(client, "admin", "Admin123!")
        res = client.get("/admin")
        assert res.status_code == 200
        users = res.get_json()["users"]
        assert {u["role"] for u in users} == {"user", "admin"}


class TestRegistrationAndLoginFlow:
    def test_register_then_login(self, client):
        res = client.post(
            "/register",
            json={"username": "bob", "email": "bob@example.com", "password": "Secret123"},
        )
        assert res.status_code == 201
        res = _login(client, "bob", "Secret123")
        assert res.status_code == 200
        assert res.get_json()["role"] == "user"

    def test_login_with_wrong_password(self, client):
        client.post(
            "/register",
            json={"username": "bob", "email": "bob@example.com", "password": "Secret123"},
        )
        res = _login(client, "bob", "Wrong123")
        assert res.status_code == 401
