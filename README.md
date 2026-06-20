# SafeVault — Secure Web Application

SafeVault is a secure web application for managing sensitive data (user
credentials and financial records). This repository is the consolidated
submission for the three-part **"Securing the SafeVault Application"** project,
built with assistance from **Microsoft Copilot** (and Claude Code):

1. **Activity 1** — Input validation & SQL-injection prevention
2. **Activity 2** — Authentication & role-based access control (RBAC)
3. **Activity 3** — Debugging & resolving SQL-injection / XSS vulnerabilities

The project is implemented in **Python 3** with **Flask**, **SQLite**, and
**bcrypt**, and ships with a **pytest** suite of **87 tests** that simulate
real attack payloads.

---

## Project structure

```
safevault/
├── __init__.py              # Flask app factory
├── validation.py            # Activity 1: input sanitization & XSS escaping
├── db.py                    # Activity 1: parameterized SQL queries
├── auth.py                  # Activity 2: bcrypt hashing + login
├── authorization.py         # Activity 2: RBAC (role_required decorator)
├── routes.py                # HTTP endpoints (/register /login /admin /search ...)
└── examples/
    └── vulnerable_vs_fixed.py   # Activity 3: documented vulnerable vs. fixed code
tests/                       # pytest suite (SQLi, XSS, auth, RBAC, HTTP)
run.py                       # Dev server entry point
requirements.txt
pytest.ini
```

---

## Quick start

```bash
python -m pip install -r requirements.txt

# Run the test suite (87 tests)
python -m pytest

# Run the dev server (creates safevault.db)
python run.py   # http://127.0.0.1:5000
```

### Example API calls

```bash
# Register a user
curl -X POST localhost:5000/register \
  -H "Content-Type: application/json" \
  -d '{"username":"alice","email":"alice@example.com","password":"Secret123"}'

# Log in (starts a session)
curl -X POST localhost:5000/login -c cookies.txt -H "Content-Type: application/json" \
  -d '{"username":"alice","password":"Secret123"}'

# Search records (parameterized query + escaped output)
curl -b cookies.txt "localhost:5000/search?q=payroll"
```

---

## Security controls implemented

### Activity 1 — Input validation & SQL-injection prevention
- **`validation.py`** — `sanitize_input()` strips SQL metacharacters (`'`, `"`,
  `;`, `--`, `/* */`, `@@`, `#`) and control/null bytes; `validate_username`,
  `validate_email`, and `validate_password` enforce strict input policies;
  `escape_html()` neutralizes XSS payloads by HTML-encoding `& < > " '`.
- **`db.py`** — *every* query uses **parameterized statements** (`?` placeholders
  bound by the sqlite3 driver). User data is never concatenated into SQL.

### Activity 2 — Authentication & RBAC
- **`auth.py`** — passwords are hashed with **bcrypt** (cost factor 12, unique
  salt). `verify_password` uses `bcrypt.checkpw` (constant-time). Login returns
  an identical error for "unknown user" and "wrong password" to prevent
  **username enumeration**.
- **`authorization.py`** — `role_required("admin")` decorator protects the
  Admin Dashboard. Roles (`user`, `admin`) are re-read from the DB on each
  request, so privilege changes take effect immediately. Anonymous → 401,
  authenticated-but-unauthorized → 403.

### Activity 3 — Debugging & resolving vulnerabilities
- **`examples/vulnerable_vs_fixed.py`** documents three real issues found
  during review and shows the fix applied throughout the codebase (see table
  below).

---

## Vulnerability summary (Activity 3)

| # | Vulnerability | Insecure pattern | Fix applied | Where |
|---|---------------|------------------|-------------|-------|
| 1 | **SQL injection** | SQL built with f-string interpolation: `f"SELECT * FROM users WHERE username = '{username}'"` — payload `admin'--` bypasses login | Replaced with **parameterized query**: `WHERE username = ?` bound by the driver | `db.py` (all queries), `examples/vulnerable_vs_fixed.py` |
| 2 | **Stored / reflected XSS** | User content written into HTML without escaping: `f"<h1>{title}</h1>"` — `<script>` payload executes | **HTML-escape** all user content on output (`html.escape(..., quote=True)`) | `validation.escape_html`, `routes.search` |
| 3 | **Username enumeration** | Distinct login errors ("No such user" vs "Wrong password") let attackers enumerate accounts | Single generic error `"Invalid username or password."` for both cases | `auth.authenticate_user` |
| 4 | **Weak passwords** | No password policy | Enforced min length + mixed case + digit; bcrypt hashing | `validation.validate_password` |
| 5 | **Session fixation** | Session id retained across login | `session.clear()` on successful login | `routes.login` |

### How the fixes were verified
The pytest suite asserts each fix against live attack payloads:

- **SQL injection** — `tests/test_sql_injection.py` sends 7 payloads
  (`' OR '1'='1`, `admin'--`, `'; DROP TABLE users; --`, `UNION SELECT ...`,
  …) and asserts they neither return unauthorized rows nor drop the `users`
  table. A paired test proves the *vulnerable* code is exploitable with the
  same payload, confirming the fix is meaningful.
- **XSS** — `tests/test_xss.py` injects `<script>`, `<img onerror=…>`,
  `<body onload=…>` payloads and asserts no live tag survives escaping.
- **Authentication** — `tests/test_auth.py` covers correct/wrong passwords,
  unknown users, duplicate registration, weak passwords, and SQL-injection
  login bypass.
- **RBAC** — `tests/test_authorization.py` confirms anonymous users get 401,
  regular users get 403 on `/admin`, and admins get 200.
- **HTTP end-to-end** — `tests/test_http_endpoints.py` drives the running app
  to confirm injection/XSS resistance at the API surface.

### How Copilot assisted in the debugging process
Copilot was used to:
1. **Audit** the codebase and flag insecure patterns (string-concatenated SQL,
   unescaped output, distinct login error messages).
2. **Generate** the corrected code (parameterized queries, `html.escape`, a
   `role_required` decorator, bcrypt hashing).
3. **Produce** the attack-simulation tests, including the parametrized
   SQL-injection and XSS payload lists.
4. **Explain** *why* each fix works (e.g., that a bound parameter is treated as
   a literal value and cannot alter query structure), which informed the
   comments throughout this codebase.

Copilot accelerates the mechanics, but every suggestion was reviewed, since
LLMs can also emit insecure code — parameterization and output escaping were
verified independently by the test suite rather than taken on trust.

---

## Rubric mapping

| Points | Requirement | Location |
|--------|-------------|----------|
| 5 | GitHub repository | this repo |
| 5 | Copilot-generated secure code for input validation & SQL-injection prevention | `validation.py`, `db.py` |
| 5 | Authentication & RBAC | `auth.py`, `authorization.py`, `routes.py` |
| 5 | Debugged SQL-injection & XSS | `examples/vulnerable_vs_fixed.py`, fixes across modules |
| 5 | Generated & executed tests | `tests/` (87 passing) |
| 5 | Vulnerability summary | this README, "Vulnerability summary" section |

---

## License

See [LICENSE](LICENSE).
