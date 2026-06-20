using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using SafeVault.Data;
using SafeVault.Models;
using SafeVault.Security;
using SafeVault.Services;

namespace SafeVault.Tests;

/// <summary>
/// Builds an isolated SQLite database (file) with the Identity schema created
/// and one demo user seeded, returning the scoped services the tests need.
/// Disposing deletes the temp file.
/// </summary>
public sealed class SqliteTestDb : IDisposable
{
    private readonly ServiceProvider _root;
    public ApplicationDbContext Db { get; }
    public string DbPath { get; }

    public SqliteTestDb()
    {
        DbPath = Path.Combine(Path.GetTempPath(), $"safevault-sqli-{Guid.NewGuid()}.db");

        var services = new ServiceCollection();
        services.AddLogging();
        services.AddDbContext<ApplicationDbContext>(o => o.UseSqlite($"Data Source={DbPath}"));
        services.AddIdentity<ApplicationUser, IdentityRole>()
                .AddEntityFrameworkStores<ApplicationDbContext>();
        services.AddScoped<IPasswordHasher<ApplicationUser>, BcryptPasswordHasher<ApplicationUser>>();

        _root = services.BuildServiceProvider(validateScopes: true);
        var scope = _root.CreateScope();

        Db = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();
        Db.Database.EnsureCreated();

        SeedAsync(Db, scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>()).GetAwaiter().GetResult();
    }

    private static async Task SeedAsync(ApplicationDbContext db, UserManager<ApplicationUser> users)
    {
        // A normal user to search for.
        var alice = new ApplicationUser { UserName = "alice@safevault.local", Email = "alice@safevault.local", EmailConfirmed = true, DisplayName = "Alice" };
        await users.CreateAsync(alice, "Alice#1234");
    }

    public UserRepository SecureRepo => new(Db);
    public InsecureUserRepository InsecureRepo => new(Db);

    public void Dispose()
    {
        _root.Dispose();
        try { if (File.Exists(DbPath)) File.Delete(DbPath); } catch { /* ignore */ }
    }
}
