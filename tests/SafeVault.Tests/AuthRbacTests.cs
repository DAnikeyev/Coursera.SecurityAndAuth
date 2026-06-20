using System.Net;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;

namespace SafeVault.Tests;

/// <summary>
/// Activity 2 — authentication and role-based authorization (RBAC).
/// Drives the real login form and the role-protected Admin Dashboard through
/// the in-process test server.
/// </summary>
[TestFixture]
public class AuthRbacTests
{
    private SafeVaultWebAppFactory _factory = null!;

    [SetUp]
    public void SetUp() => _factory = new SafeVaultWebAppFactory();

    [TearDown]
    public void TearDown() => _factory.Dispose();

    private HttpClient Client(bool followRedirects = false) =>
        _factory.CreateClient(new WebApplicationFactoryClientOptions
        {
            AllowAutoRedirect = followRedirects,
            HandleCookies = true
        });

    // ---- Authentication: invalid credentials are rejected ----
    [Test]
    public async Task Login_WithInvalidCredentials_IsRejected()
    {
        var client = Client();
        var status = await client.LoginAsync("admin@safevault.local", "WrongPassword#1");
        // Failure re-renders the login page (200), not a redirect (302).
        Assert.That(status, Is.EqualTo(HttpStatusCode.OK),
            "Invalid credentials must not authenticate the user.");
    }

    [Test]
    public async Task Login_WithUnknownUser_IsRejected()
    {
        var client = Client();
        var status = await client.LoginAsync("nobody@safevault.local", "Whatever#1");
        Assert.That(status, Is.EqualTo(HttpStatusCode.OK));
    }

    [Test]
    public async Task Login_WithValidCredentials_Succeeds()
    {
        var client = Client();
        var status = await client.LoginAsync("admin@safevault.local", "Admin#1234");
        Assert.That(status, Is.EqualTo(HttpStatusCode.Redirect),
            "Valid credentials should authenticate and redirect.");
    }

    // ---- Authorization: Admin Dashboard is role-gated ----
    [Test]
    public async Task AdminDashboard_RequiresAuthentication()
    {
        var client = Client();
        var response = await client.GetAsync("/Admin/Dashboard");
        // Unauthenticated → redirected to the login page.
        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.Redirect));
        Assert.That(response.Headers.Location!.ToString(), Does.Contain("/Account/Login"));
    }

    [Test]
    public async Task AdminDashboard_DeniedToNonAdminUser()
    {
        var client = Client();
        await client.LoginAsync("user@safevault.local", "User#1234");

        var response = await client.GetAsync("/Admin/Dashboard");
        // Authenticated but wrong role → access denied.
        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.Redirect));
        Assert.That(response.Headers.Location!.ToString(), Does.Contain("AccessDenied"));
    }

    [Test]
    public async Task AdminDashboard_AllowedToAdminUser()
    {
        var client = Client();
        await client.LoginAsync("admin@safevault.local", "Admin#1234");

        var response = await client.GetAsync("/Admin/Dashboard");
        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.OK),
            "An Admin user must reach the dashboard.");
    }

    // ---- Bcrypt password hashing is actually in use ----
    [Test]
    public async Task Passwords_AreHashedWithBcrypt_InDatabase()
    {
        // Reach into the seeded database and confirm the stored hash is a bcrypt
        // hash (bcrypt hashes start with $2), never plaintext.
        await using var scope = _factory.Services.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<SafeVault.Data.ApplicationDbContext>();
        var admin = db.Users.Single(u => u.Email == "admin@safevault.local");

        Assert.That(admin.PasswordHash, Does.StartWith("$2"),
            "Password must be bcrypt-hashed, not stored in plaintext.");
        Assert.That(admin.PasswordHash, Is.Not.EqualTo("Admin#1234"));
    }
}
