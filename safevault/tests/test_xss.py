"""XSS tests (Activity 1/3, Step 4).

Confirms that user-controlled content is HTML-escaped on output so that script
payloads cannot execute in a browser.
"""

from __future__ import annotations

import pytest

from safevault.examples.vulnerable_vs_fixed import _vulnerable_render, secure_render
from safevault.validation import escape_html

XSS_PAYLOADS = [
    "<script>alert('xss')</script>",
    '"><script>alert(1)</script>',
    "<img src=x onerror=alert(1)>",
    "javascript:alert(1)",
    "<body onload=alert(1)>",
]


@pytest.mark.parametrize("payload", XSS_PAYLOADS)
def test_escape_html_neutralizes_payload(payload):
    escaped = escape_html(payload)
    # The defense is that no live HTML tag survives: every '<' from the payload
    # must be encoded as '&lt;'. Attribute names like 'onerror=' may appear as
    # inert text - that is harmless because there is no tag to attach them to.
    assert "<script" not in escaped.lower()
    assert "<img" not in escaped.lower()
    assert "<body" not in escaped.lower()
    if "<" in payload:  # every payload angle bracket must be encoded
        assert "&lt;" in escaped


@pytest.mark.parametrize("payload", XSS_PAYLOADS)
def test_secure_render_neutralizes_payload(payload):
    rendered = secure_render(payload)
    # Only our own template tags (<h1>) may appear; payload tags must not.
    assert "<script" not in rendered.lower()
    assert "<img" not in rendered.lower()
    assert "<body" not in rendered.lower()
    if "<" in payload:
        assert "&lt;" in rendered


def test_vulnerable_render_is_exploitable():
    """Proof that the buggy code emitted the payload verbatim."""
    payload = "<script>alert(1)</script>"
    assert "<script>alert(1)</script>" in _vulnerable_render(payload)
