"""Shared pytest fixtures for the SafeVault test suite."""

from __future__ import annotations

import sqlite3

import pytest

from safevault import create_app
from safevault.db import get_connection, init_db


@pytest.fixture()
def conn() -> sqlite3.Connection:
    """A fresh in-memory SQLite database for each test."""
    connection = get_connection(":memory:")
    init_db(connection)
    yield connection
    connection.close()


@pytest.fixture()
def app():
    """A fresh Flask app with an in-memory DB and testing enabled."""
    application = create_app(db_path=":memory:", secret_key="test-secret")
    application.config["TESTING"] = True
    yield application


@pytest.fixture()
def client(app):
    """A Flask test client wired to the ``app`` fixture."""
    return app.test_client()
