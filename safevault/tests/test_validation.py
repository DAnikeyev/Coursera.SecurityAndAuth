"""Tests for input validation and sanitization (Activity 1, Step 2/4)."""

from __future__ import annotations

import pytest

from safevault.validation import (
    ValidationError,
    escape_html,
    is_safe_search_term,
    sanitize_input,
    validate_email,
    validate_password,
    validate_username,
)


class TestSanitizeInput:
    def test_strips_whitespace(self):
        assert sanitize_input("  alice  ") == "alice"

    def test_removes_sql_metacharacters(self):
        assert sanitize_input("ali'ce") == "alice"
        assert sanitize_input("a; DROP--") == "a DROP"

    def test_handles_none_and_non_string(self):
        assert sanitize_input(None) == ""
        assert sanitize_input(123) == "123"

    def test_strips_null_bytes(self):
        # Null bytes are used to truncate strings in some C-based backends.
        assert "\x00" not in sanitize_input("ab\x00cd")


class TestEscapeHtml:
    def test_escapes_xss_payload(self):
        payload = "<script>alert('xss')</script>"
        escaped = escape_html(payload)
        assert "<script>" not in escaped
        assert "&lt;script&gt;" in escaped

    def test_escapes_quotes(self):
        assert escape_html('"onerror=alert(1)') == "&quot;onerror=alert(1)"


class TestValidateUsername:
    def test_valid(self):
        assert validate_username("alice_99") == "alice_99"

    @pytest.mark.parametrize(
        "bad",
        ["ab", "x" * 33, "bad name", "user(name)", "user@name", ""],
    )
    def test_invalid(self, bad):
        with pytest.raises(ValidationError):
            validate_username(bad)


class TestValidateEmail:
    def test_valid(self):
        assert validate_email("Alice@Example.COM") == "alice@example.com"

    @pytest.mark.parametrize("bad", ["notanemail", "a@b", "@x.com", "a@b.c", ""])
    def test_invalid(self, bad):
        with pytest.raises(ValidationError):
            validate_email(bad)


class TestValidatePassword:
    def test_valid(self):
        assert validate_password("Secret123") == "Secret123"

    @pytest.mark.parametrize("bad", ["short", "alllowercase1", "ALLUPPERCASE1", "NoDigitsHere"])
    def test_invalid(self, bad):
        with pytest.raises(ValidationError):
            validate_password(bad)


class TestSearchTermSafety:
    def test_clean_term(self):
        assert is_safe_search_term("quarterly report")

    def test_injection_terms(self):
        assert not is_safe_search_term("' OR 1=1 --")
        assert not is_safe_search_term("UNION SELECT password FROM users")
        assert not is_safe_search_term("<script>alert(1)</script>")
