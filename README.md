# SafeVault

A secure ASP.NET Core web application that manages sensitive data with strong
defenses against the most common web vulnerabilities — **SQL injection** and
**cross-site scripting (XSS)** — together with **authentication** and
**role-based access control (RBAC)** built on ASP.NET Core Identity.

This repository is the consolidated submission for the three-part Coursera
*Security & Authentication* project (Activities 1–3).

---

## Tech stack

| Concern | Choice |
|---|---|
| Platform | ASP.NET Core 8.0 (MVC) |
| AuthN / AuthZ | ASP.NET Core Identity + roles |
| Password hashing | **bcrypt** (work factor 12), via a custom `IPasswordHasher<T>` |
| Database | SQLite via Entity Framework Core 8 |
| Raw data access | Parameterized queries (`Microsoft.Data.Sqlite`) |
| Testing | NUnit 3 (+ `WebApplicationFactory` integration tests) |

---

## Repository layout

```
SafeVault.sln
docs/
  database.sql                 # Reference schema + parameterized-query patterns
src/SafeVault/                 # The web application
  Program.cs                   # DI, Identity, bcrypt hasher, security headers
  Data/
    ApplicationDbContext.cs    # EF Core Identity context
    DbInitializer.cs           # Seeds Admin/User roles + demo accounts
  Models/
    ApplicationUser.cs         # Identity user + DisplayName
    AccountViewModels.cs       # Register / Login / Submit view models
    UserMessage.cs             # User-generated content (XSS surface)
  Services/
    InputValidator.cs          # Input validation & sanitization (Activity 1)
    IUserRepository.cs         # Parameterized data access contract
    UserRepository.cs          # SECURE: SqliteParameter-bound queries
  Security/
    BcryptPasswordHasher.cs    # bcrypt password hashing (Activity 2)
    InsecureUserRepository.cs  # DEMONSTRATION of the vulnerable pattern (Activity 3)
  Controllers/                 # Home, Account, Admin ([Authorize(Roles=Admin)]), Vault
  Views/                       # Razor views (HTML-encoded output)
tests/SafeVault.Tests/         # Security + auth test suite (NUnit)
  InputValidationTests.cs      # SQLi/XSS input rejection
  SqlInjectionTests.cs         # secure vs insecure query comparison
  XssTests.cs                  # output encoding end-to-end
  AuthRbacTests.cs             # login + role-gated Admin Dashboard
```

---

## How to run

```bash
# Build the whole solution
dotnet build

# Run the security + auth test suite
dotnet test

# Run the web app (creates a local safevault.db and seeds demo users)
dotnet run --project src/SafeVault
```

Browse to the printed URL (e.g. `https://localhost:5001`). The DB and demo
accounts are created automatically on first launch.

### Demo accounts

| Role | Email | Password |
|---|---|---|
| Admin | `admin@safevault.local` | `Admin#1234` |
| User  | `user@safevault.local`  | `User#1234`  |

---

## Activity mapping

### Activity 1 — Input validation & SQL injection prevention
- `Services/InputValidator.cs` validates usernames/emails against allow-lists and
  a known SQLi/XSS signature list; sanitizes free-form text.
- `Services/UserRepository.cs` performs **every** read/write through
  parameterized `SqliteParameter` queries — user input is bound as data, never
  interpolated into SQL.
- Tested by `InputValidationTests.cs` and `SqlInjectionTests.cs`.

### Activity 2 — Authentication & role-based authorization
- ASP.NET Core Identity stores users and roles (`Admin`, `User`).
- `Security/BcryptPasswordHasher.cs` replaces Identity's default PBKDF2 with
  **bcrypt**, satisfying the requirement to hash passwords with a slow, salted
  algorithm (bcrypt / Argon2 family).
- `AccountController` implements registration, login (with lockout and
  user-enumeration-safe error messages), and logout.
- `AdminController` is decorated with `[Authorize(Roles = "Admin")]`, so the
  **Admin Dashboard is reachable only by admins** — pure RBAC.
- Tested by `AuthRbacTests.cs` (valid/invalid login, anonymous / user / admin
  access to the dashboard, and a check that the stored password is a bcrypt hash).

### Activity 3 — Debugging & resolving vulnerabilities
- `Security/InsecureUserRepository.cs` deliberately reproduces the vulnerable
  string-concatenation query so the fix is provable.
- `SqlInjectionTests.cs` shows the insecure query **leaking every row** for an
  `' OR '1'='1` payload, while the parameterized repository returns nothing.
- XSS is fixed with **input sanitization + Razor output encoding** + a strict
  `Content-Security-Policy` / `X-Content-Type-Options` header (see `Program.cs`).
- Tested by `XssTests.cs`, which submits `<script>alert(...)</script>` and
  asserts it is rendered as encoded text, never as executable markup.

---

## Rubric checklist (30 pts)

| Points | Requirement | Where |
|---|---|---|
| 5 | GitHub repository | this repo |
| 5 | Secure code for input validation & SQL injection prevention | `InputValidator.cs`, `UserRepository.cs` |
| 5 | Authentication & authorization incl. RBAC | `BcryptPasswordHasher.cs`, `AccountController`, `AdminController` (`[Authorize(Roles="Admin")]`) |
| 5 | Debug & resolve SQL injection + XSS | `InsecureUserRepository.cs` vs `UserRepository.cs`; output encoding + CSP in `Program.cs` |
| 5 | Generate & execute security tests | `tests/SafeVault.Tests/` — **31 passing tests** |
| 5 | Vulnerability summary (below) | this README |

---

## Vulnerability summary

### Vulnerabilities identified

1. **SQL injection (CWE-89)** — code that builds SQL with string concatenation
   lets an attacker append `' OR '1'='1`, `UNION SELECT`, or stacked statements
   (`; DROP TABLE …`), bypassing filters and reading/destroying data.
   Demonstrated in `Security/InsecureUserRepository.cs`.
2. **Cross-site scripting / stored XSS (CWE-79)** — echoing user-supplied text
   into a page without escaping lets an attacker inject `<script>` that runs in
   other users' browsers, stealing sessions or performing actions on their
   behalf.
3. **Plaintext / weak password storage** — storing or comparing raw passwords
   exposes credentials if the database leaks.
4. **Missing / improper access control** — failing to gate sensitive features
   (admin tools) by role lets any authenticated user reach them.
5. **Missing security headers** — without `Content-Security-Policy` /
   `X-Content-Type-Options` / `X-Frame-Options`, the app is more exposed to
   injection and clickjacking.

### Fixes applied

| Vulnerability | Fix |
|---|---|
| SQL injection | **Parameterized queries** exclusively (`SqliteParameter`); never concatenate user input into SQL. Validated at the input boundary too. |
| XSS | Input **sanitization** (`InputValidator`) + **HTML output encoding** by Razor (`@Model.Content`) + a strict **CSP** header. Defense in depth. |
| Weak passwords | **bcrypt** password hashing (work factor 12) via Identity's `IPasswordHasher<T>`. |
| Access control | ASP.NET Core Identity authentication + **RBAC** with `[Authorize(Roles = "Admin")]` on the Admin Dashboard; lockout + enumeration-safe login errors. |
| Security headers | `Content-Security-Policy`, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY` added in `Program.cs`. |

### How Microsoft Copilot assisted

Copilot was used throughout to: draft the initial validation rules and the
SQLi/XSS signature regex, scaffold the parameterized repository methods and the
bcrypt `IPasswordHasher<T>` implementation, generate the NUnit attack-scenario
tests (including the secure-vs-insecure comparison), and review the request
pipeline for missing middleware and headers. It accelerated the boilerplate so
the focus stayed on the security reasoning behind each fix.

---

## Test results

```
dotnet test
Passed! - Failed: 0, Passed: 31, Skipped: 0, Total: 31
```
