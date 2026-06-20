using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using SafeVault.Data;
using SafeVault.Models;

namespace SafeVault.Security;

//  ===================================================================================
//  DELIBERATELY INSECURE — DO NOT USE IN PRODUCTION
//  ===================================================================================
//  This class exists only to demonstrate the vulnerable pattern that the secure
//  SafeVault.Data / UserRepository replaces (Activity 3). It performs SQL by
//  string concatenation, which is the textbook SQL injection vulnerability.
//
//  The security tests prove:
//    * SearchInsecureAsync is exploitable (an injected payload returns rows it
//      should not, or mutates the query).
//    * The parameterized UserRepository.SearchAsync is immune to the same payload.
//
//  It is intentionally NOT registered in the DI container.
//  ===================================================================================

public sealed class InsecureUserRepository
{
    private readonly ApplicationDbContext _db;

    public InsecureUserRepository(ApplicationDbContext db) => _db = db;

    /// <summary>
    /// VULNERABLE: user input is concatenated directly into the SQL text.
    /// A payload such as <c>' OR '1'='1</c> returns every row in the table.
    /// </summary>
    public async Task<IReadOnlyList<ApplicationUser>> SearchInsecureAsync(string keyword)
    {
        // ❌ String concatenation: the textbook SQL injection bug.
        var sql =
            "SELECT Id, UserName, Email, DisplayName, CreatedAtUtc " +
            "FROM AspNetUsers WHERE UserName LIKE '%" + keyword + "%' " +
            "OR Email LIKE '%" + keyword + "%';";

        var connection = (SqliteConnection)_db.Database.GetDbConnection();
        await using var cmd = connection.CreateCommand();
        cmd.CommandText = sql;

        if (connection.State != System.Data.ConnectionState.Open)
        {
            await connection.OpenAsync();
        }

        var results = new List<ApplicationUser>();
        await using var reader = await cmd.ExecuteReaderAsync();
        while (await reader.ReadAsync())
        {
            int Ordinal(string name) => reader.GetOrdinal(name);
            results.Add(new ApplicationUser
            {
                Id = reader.GetString(Ordinal("Id")),
                UserName = reader.IsDBNull(Ordinal("UserName")) ? null : reader.GetString(Ordinal("UserName")),
                Email = reader.IsDBNull(Ordinal("Email")) ? null : reader.GetString(Ordinal("Email")),
                DisplayName = reader.IsDBNull(Ordinal("DisplayName")) ? string.Empty : reader.GetString(Ordinal("DisplayName")),
                CreatedAtUtc = reader.GetDateTime(Ordinal("CreatedAtUtc"))
            });
        }

        return results;
    }
}
