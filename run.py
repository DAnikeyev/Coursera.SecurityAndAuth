"""Entry point to run the SafeVault development server.

    python run.py
"""

from __future__ import annotations

from safevault import create_app

app = create_app(db_path="safevault.db", secret_key="replace-this-in-production")

if __name__ == "__main__":
    app.run(debug=True, port=5000)
