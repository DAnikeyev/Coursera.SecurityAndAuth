using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using SafeVault.Data;

namespace SafeVault.Tests;

/// <summary>
/// Bootstraps the SafeVault web app in-process for integration testing, pointing
/// EF Core at a unique temp SQLite file so tests are fully isolated and the
/// role/user seed runs against it. Created databases are deleted on dispose.
/// </summary>
public class SafeVaultWebAppFactory : WebApplicationFactory<Program>
{
    private readonly string _dbPath;

    public SafeVaultWebAppFactory()
    {
        _dbPath = Path.Combine(Path.GetTempPath(), $"safevault-test-{Guid.NewGuid()}.db");
    }

    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        builder.UseEnvironment("Testing");

        builder.ConfigureServices(services =>
        {
            // Remove the app's DbContext registration and re-add it pointing
            // at our isolated temp database.
            var descriptor = services.Single(
                d => d.ServiceType == typeof(DbContextOptions<ApplicationDbContext>));
            services.Remove(descriptor);

            services.AddDbContext<ApplicationDbContext>(options =>
                options.UseSqlite($"Data Source={_dbPath}"));
        });
    }

    protected override void Dispose(bool disposing)
    {
        base.Dispose(disposing);
        try { if (File.Exists(_dbPath)) File.Delete(_dbPath); } catch { /* ignore */ }
    }
}
