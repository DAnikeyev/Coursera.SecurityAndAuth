"""SQL-injection tests (Activity 1, Step 4 & Activity 3, Step 4).

These tests simulate SQL-injection payloads against the parameterized queries in
``safevault.db`` and confirm the application does not execute injected SQL.
"""

from __future__ import annotations

import pytest

from safevault.auth import hash_password, register_user
from safevault.db import (
    add_record,
    create_user,
    get_user_by_username,
    search_records_by_title,
)
from safevault.examples.vulnerable_vs_fixed import (
    _vulnerable_get_user,
    secure_get_user,
)

INJECTION_PAYLOADS = [
    "admin'--",
    "admin' --",
    "' OR '1'='1",
    "' OR 1=1 --",
    "'; DROP TABLE users; --",
    "admin'/*",
    "' UNION SELECT id, username, password_hash, email, role FROM users --",
]


@pytest.fixture()
def seeded_conn(conn):
    create_user(conn, "admin", "admin@example.com", hash_password("Admin123!"), "admin")
    create_user(conn, "alice", "alice@example.com", hash_password("Alice123!"), "user")
    add_record(conn, 1, "Payroll Q1", "secret payroll data")
    add_record(conn, 2, "Public Memo", "hello world")
    return conn


class TestParameterizedUserLookup:
    @pytest.mark.parametrize("payload", INJECTION_PAYLOADS)
    def test_injection_does_not_return_admin(self, seeded_conn, payload):
        """An injection payload must not authenticate as another user."""
        result = get_user_by_username(seeded_conn, payload)
        assert result is None or result["username"] == payload.strip("'\"; ")

    def test_legitimate_lookup_still_works(self, seeded_conn):
        user = get_user_by_username(seeded_conn, "admin")
        assert user is not None
        assert user["role"] == "admin"


class TestParameterizedSearch:
    @pytest.mark.parametrize("payload", INJECTION_PAYLOADS)
    def test_injection_does_not_leak_all_rows(self, seeded_conn, payload):
        """The search must not return every record (which an unparameterized
        ``... OR '1'='1`` query would)."""
        results = search_records_by_title(seeded_conn, payload)
        assert results == []

    def test_legitimate_search_works(self, seeded_conn):
        results = search_records_by_title(seeded_conn, "Payroll")
        assert len(results) == 1
        assert results[0]["title"] == "Payroll Q1"


class TestUsersTableIntact:
    def test_drop_table_injection_is_inert(self, seeded_conn):
        """``'; DROP TABLE users; --`` must not actually drop the table."""
        get_user_by_username(seeded_conn, "x'; DROP TABLE users; --")
        # If the table had been dropped, this would raise.
        assert get_user_by_username(seeded_conn, "admin") is not None


class TestVulnerableVsFixed:
    """Demonstrates that the *vulnerable* code IS exploitable while the fixed
    code is not - the proof that Activity 3's fix is meaningful."""

    def test_vulnerable_code_is_exploitable(self, seeded_conn):
        # The classic auth-bypass: close the string and comment out the rest.
        leaked = _vulnerable_get_user(seeded_conn, "admin'--")
        assert leaked is not None
        assert leaked["username"] == "admin"

    @pytest.mark.parametrize("payload", ["admin'--", "' OR '1'='1"])
    def test_fixed_code_blocks_same_payload(self, seeded_conn, payload):
        assert secure_get_user(seeded_conn, payload) is None
