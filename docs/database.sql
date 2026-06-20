-- ============================================================================
-- SafeVault — reference database schema
-- ============================================================================
-- In the running application this schema is created automatically by Entity
-- Framework Core (ApplicationDbContext) against a SQLite database. This file
-- documents the tables and shows the *parameterized* query patterns the
-- application uses instead of string concatenation (SQL injection defense).
--
-- The original activity brief used MySQL syntax (AUTO_INCREMENT). The concepts
-- are identical; SQLite is used here so the app runs with zero external setup.
-- ============================================================================

-- Users, roles and the join tables are the standard ASP.NET Core Identity schema:
--   AspNetUsers, AspNetRoles, AspNetUserRoles, AspNetUserClaims,
--   AspNetUserLogins, AspNetUserTokens, AspNetRoleClaims.
-- AspNetUsers is extended with DisplayName and CreatedAtUtc (see ApplicationUser).

CREATE TABLE IF NOT EXISTS UserMessages (
    Id            INTEGER PRIMARY KEY AUTOINCREMENT,
    Username      VARCHAR(100)  NOT NULL,
    Content       TEXT          NOT NULL,
    CreatedAtUtc  TEXT          NOT NULL
);

-- ----------------------------------------------------------------------------
-- ALWAYS parameterize. Bind user input through placeholders/parameters so it
-- can never be parsed as SQL. This is implemented in UserRepository.cs using
-- SqliteParameter.
-- ----------------------------------------------------------------------------

-- Example: safe search
--   SELECT Id, UserName, Email, DisplayName, CreatedAtUtc
--   FROM   AspNetUsers
--   WHERE  UserName LIKE @keyword OR Email LIKE @keyword;
-- (with @keyword bound to '%' + value + '%')

-- Example: safe insert
--   INSERT INTO UserMessages (Username, Content, CreatedAtUtc)
--   VALUES (@username, @content, @now);
