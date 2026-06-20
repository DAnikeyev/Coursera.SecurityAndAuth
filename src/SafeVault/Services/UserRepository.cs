using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using SafeVault.Data;
using SafeVault.Models;

namespace SafeVault.Services;

/// <summary>
/// SQLite-backed implementation of <see cref="IUserRepository"/>.
///
/// IMPORTANT: All queries are parameterized. User input is bound via
/// <see cref="SqliteParameter"/> values, so it is treated strictly as data and
/// can never alter the structure of the SQL statement. Compare this with
/// <see cref="SafeVault.Security.InsecureUserRepository"/>, which demonstrates
/// the vulnerable string-concatenation pattern this replaces.
/// </summary>
public sealed class UserRepository : IUserRepository
{
    private readonly ApplicationDbContext _db;

    public UserRepository(ApplicationDbContext db)
    {
        _db = db;
    }

    public async Task<ApplicationUser?> GetByEmailAsync(string email)
    {
        // Parameterized query: @email is a bound parameter, not interpolated text.
        const string sql =
            "SELECT u.Id, u.UserName, u.Email, u.DisplayName, u.CreatedAtUtc " +
            "FROM AspNetUsers u WHERE u.NormalizedEmail = @email LIMIT 1;";

        await using var cmd = BuildCommand(sql, new SqliteParameter("@email", NormalizeEmail(email)));
        await OpenAsync(cmd);

        await using var reader = await cmd.ExecuteReaderAsync();
        if (!await reader.ReadAsync())
        {
            return null;
        }

        return MapUser(reader);
    }

    public async Task<IReadOnlyList<ApplicationUser>> SearchAsync(string keyword)
    {
        // The keyword is bound as a parameter to a LIKE clause. Even if a caller
        // supplies "'; DROP TABLE AspNetUsers; --", it is treated as a literal
        // search string and cannot break out of the statement.
        var pattern = $"%{keyword}%";
        const string sql =
            "SELECT u.Id, u.UserName, u.Email, u.DisplayName, u.CreatedAtUtc " +
            "FROM AspNetUsers u WHERE u.UserName LIKE @kw OR u.Email LIKE @kw " +
            "ORDER BY u.UserName;";

        await using var cmd = BuildCommand(sql, new SqliteParameter("@kw", pattern));
        await OpenAsync(cmd);

        var results = new List<ApplicationUser>();
        await using var reader = await cmd.ExecuteReaderAsync();
        while (await reader.ReadAsync())
        {
            results.Add(MapUser(reader));
        }

        return results;
    }

    public async Task AddMessageAsync(string username, string content)
    {
        const string sql =
            "INSERT INTO UserMessages (Username, Content, CreatedAtUtc) " +
            "VALUES (@username, @content, @now);";

        await using var cmd = BuildCommand(
            sql,
            new SqliteParameter("@username", username),
            new SqliteParameter("@content", content),
            new SqliteParameter("@now", DateTime.UtcNow.ToString("O")));

        await OpenAsync(cmd);
        await cmd.ExecuteNonQueryAsync();
    }

    public async Task<IReadOnlyList<UserMessage>> GetMessagesAsync()
    {
        const string sql =
            "SELECT Id, Username, Content, CreatedAtUtc FROM UserMessages " +
            "ORDER BY CreatedAtUtc DESC LIMIT 100;";

        await using var cmd = BuildCommand(sql);
        await OpenAsync(cmd);

        var results = new List<UserMessage>();
        await using var reader = await cmd.ExecuteReaderAsync();
        while (await reader.ReadAsync())
        {
            results.Add(new UserMessage
            {
                Id = reader.GetInt32(reader.GetOrdinal("Id")),
                Username = reader.GetString(reader.GetOrdinal("Username")),
                Content = reader.GetString(reader.GetOrdinal("Content")),
                CreatedAtUtc = reader.GetDateTime(reader.GetOrdinal("CreatedAtUtc"))
            });
        }

        return results;
    }

    // ---- Helpers ------------------------------------------------------------

    private static string NormalizeEmail(string email) => email.Trim().ToUpperInvariant();

    private SqliteCommand BuildCommand(string sql, params SqliteParameter[] parameters)
    {
        var connection = (SqliteConnection)_db.Database.GetDbConnection();
        var cmd = connection.CreateCommand();
        cmd.CommandText = sql;
        foreach (var p in parameters)
        {
            cmd.Parameters.Add(p);
        }
        return cmd;
    }

    private static async Task OpenAsync(SqliteCommand cmd)
    {
        if (cmd.Connection!.State != System.Data.ConnectionState.Open)
        {
            await cmd.Connection.OpenAsync();
        }
    }

    private static ApplicationUser MapUser(SqliteDataReader reader)
    {
        int Ordinal(string name) => reader.GetOrdinal(name);

        return new ApplicationUser
        {
            Id = reader.GetString(Ordinal("Id")),
            UserName = reader.IsDBNull(Ordinal("UserName")) ? null : reader.GetString(Ordinal("UserName")),
            Email = reader.IsDBNull(Ordinal("Email")) ? null : reader.GetString(Ordinal("Email")),
            DisplayName = reader.IsDBNull(Ordinal("DisplayName")) ? string.Empty : reader.GetString(Ordinal("DisplayName")),
            CreatedAtUtc = reader.GetDateTime(Ordinal("CreatedAtUtc"))
        };
    }
}
