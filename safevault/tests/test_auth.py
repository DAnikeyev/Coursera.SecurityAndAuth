"""Authentication tests (Activity 2, Step 4)."""

from __future__ import annotations

import pytest

from safevault.auth import (
    AuthenticationError,
    RegistrationError,
    authenticate_user,
    hash_password,
    register_user,
    verify_password,
)
from safevault.validation import ValidationError


class TestPasswordHashing:
    def test_hash_is_not_plaintext(self):
        h = hash_password("Secret123")
        assert h != "Secret123"
        assert h.startswith("$2")  # bcrypt marker

    def test_hashes_are_salt_unique(self):
        assert hash_password("Secret123") != hash_password("Secret123")

    def test_verify_correct_password(self):
        h = hash_password("Secret123")
        assert verify_password("Secret123", h) is True

    def test_verify_wrong_password(self):
        h = hash_password("Secret123")
        assert verify_password("wrong", h) is False

    def test_verify_malformed_hash(self):
        assert verify_password("Secret123", "not-a-hash") is False


class TestRegistration:
    def test_register_success(self, conn):
        uid = register_user(conn, "alice", "alice@example.com", "Secret123")
        assert uid >= 1

    def test_duplicate_username_rejected(self, conn):
        register_user(conn, "alice", "alice@example.com", "Secret123")
        with pytest.raises(RegistrationError):
            register_user(conn, "alice", "other@example.com", "Secret123")

    def test_duplicate_email_rejected(self, conn):
        register_user(conn, "alice", "alice@example.com", "Secret123")
        with pytest.raises(RegistrationError):
            register_user(conn, "alice2", "alice@example.com", "Secret123")

    def test_weak_password_rejected(self, conn):
        with pytest.raises(ValidationError):
            register_user(conn, "alice", "alice@example.com", "weak")

    def test_invalid_username_rejected(self, conn):
        with pytest.raises(ValidationError):
            register_user(conn, "x", "alice@example.com", "Secret123")


class TestAuthentication:
    @pytest.fixture()
    def registered(self, conn):
        register_user(conn, "alice", "alice@example.com", "Secret123")
        return conn

    def test_login_success(self, registered):
        user = authenticate_user(registered, "alice", "Secret123")
        assert user["username"] == "alice"

    def test_login_wrong_password(self, registered):
        with pytest.raises(AuthenticationError):
            authenticate_user(registered, "alice", "Wrong123")

    def test_login_unknown_user(self, registered):
        with pytest.raises(AuthenticationError):
            authenticate_user(registered, "ghost", "Secret123")

    @pytest.mark.parametrize(
        "payload", ["alice'--", "' OR '1'='1", "admin'/*"]
    )
    def test_login_sql_injection_fails(self, registered, payload):
        """Injection payloads must not bypass authentication."""
        with pytest.raises(AuthenticationError):
            authenticate_user(registered, payload, "anything")
