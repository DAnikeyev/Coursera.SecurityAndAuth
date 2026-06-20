using Microsoft.EntityFrameworkCore;
using SafeVault.Data;
using SafeVault.Security;

namespace SafeVault.Tests;

/// <summary>
/// Activity 1 / Activity 3 — SQL injection. The parameterized
/// <see cref="SafeVault.Services.UserRepository"/> must treat injection payloads
/// as literal data, while the deliberately-insecure string-concatenation
/// repository demonstrates the vulnerability it replaces.
/// </summary>
[TestFixture]
public class SqlInjectionTests
{
    private SqliteTestDb _db = null!;

    [SetUp]
    public void SetUp() => _db = new SqliteTestDb();

    [TearDown]
    public void TearDown() => _db.Dispose();

    // ---- The secure, parameterized repository resists injection ----
    [TestCase("' OR '1'='1")]
    [TestCase("x' OR Email LIKE '%")]
    [TestCase("'; DROP TABLE AspNetUsers; --")]
    [TestCase("alice' UNION SELECT Id, UserName, Email, DisplayName, CreatedAtUtc FROM AspNetUsers --")]
    public async Task SecureRepository_TreatsPayloadAsLiteralData(string payload)
    {
        var repo = _db.SecureRepo;

        // No exception should be thrown...
        var results = await repo.SearchAsync(payload);

        // ...and an injection like "' OR '1'='1" must NOT return every row.
        // At most it matches the literal substring in seeded data (none here).
        Assert.That(results, Is.Empty,
            $"Parameterized query leaked rows for payload: {payload}");
    }

    [Test]
    public async Task SecureRepository_FindsByHonestKeyword()
    {
        var repo = _db.SecureRepo;
        var results = await repo.SearchAsync("alice");
        Assert.That(results, Has.Count.EqualTo(1));
        Assert.That(results[0].Email, Is.EqualTo("alice@safevault.local"));
    }

    [Test]
    public async Task SecureRepository_ParameterizedInsertStoresPayloadSafely()
    {
        var repo = _db.SecureRepo;
        const string payload = "<script>alert(1)</script>"; // stored as a literal
        await repo.AddMessageAsync("alice", payload);

        var messages = await repo.GetMessagesAsync();
        Assert.That(messages, Has.Count.EqualTo(1));
        // The payload is stored verbatim as data; encoding happens on output.
        Assert.That(messages[0].Content, Is.EqualTo(payload));
    }

    // ---- The insecure repository is demonstrably exploitable ----
    [Test]
    public async Task InsecureRepository_IsExploitedByOrInjection()
    {
        var repo = _db.InsecureRepo;

        // The classic always-true tautology bypasses the WHERE clause and
        // returns rows the caller was never authorised to see.
        var leaked = await repo.SearchInsecureAsync("' OR '1'='1");

        Assert.That(leaked, Is.Not.Empty,
            "If this passes, the insecure query was NOT exploitable (unexpected). " +
            "This test documents the vulnerable behaviour the secure repo fixes.");
    }

    [Test]
    public async Task InsecureRepository_LeaksEveryRowForTautology()
    {
        var repo = _db.InsecureRepo;

        // The classic always-true tautology makes the LIKE clause match nothing
        // but the appended OR '1'='1 makes the whole WHERE true -> every row.
        var leaked = await repo.SearchInsecureAsync("%' OR '1'='1");

        Assert.That(leaked.Count, Is.GreaterThanOrEqualTo(1),
            "The concatenating query should leak all users for this payload.");
    }
}
