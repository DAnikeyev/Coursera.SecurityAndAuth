using System.Net;
using System.Net.Http.Headers;
using System.Text.RegularExpressions;
using Microsoft.AspNetCore.Mvc.Testing;

namespace SafeVault.Tests;

/// <summary>
/// Activity 3 — cross-site scripting (XSS). Verifies end-to-end that a script
/// payload submitted through the form is rendered as inert, HTML-encoded text
/// rather than executable markup.
/// </summary>
[TestFixture]
public class XssTests
{
    private SafeVaultWebAppFactory _factory = null!;

    [SetUp]
    public void SetUp() => _factory = new SafeVaultWebAppFactory();

    [TearDown]
    public void TearDown() => _factory.Dispose();

    private HttpClient CreateNoRedirectClient()
    {
        var client = _factory.CreateClient(new WebApplicationFactoryClientOptions
        {
            AllowAutoRedirect = false,
            HandleCookies = true
        });
        return client;
    }

    private static async Task<string?> GetAntiforgeryTokenAsync(HttpClient client, string path)
    {
        var html = await client.GetStringAsync(path);
        var match = Regex.Match(html, @"name=""__RequestVerificationToken""[^>]*value=""([^""]+)""");
        return match.Success ? match.Groups[1].Value : null;
    }

    [Test]
    public async Task ScriptPayload_IsHtmlEncoded_OnOutput()
    {
        var client = CreateNoRedirectClient();

        // Authenticate as the seeded admin so the [Authorize] Submit page is reachable.
        await client.LoginAsync("admin@safevault.local", "Admin#1234");

        // Submit a malicious payload in the message body.
        var token = await GetAntiforgeryTokenAsync(client, "/Vault/Submit");
        Assert.That(token, Is.Not.Null, "Submit page must render an antiforgery token.");

        var form = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["Username"] = "alice",
            ["Email"] = "alice@safevault.local",
            ["Message"] = "<script>alert('xss')</script>"
        });
        // Attach the token as a header (equivalent to the hidden field).
        var req = new HttpRequestMessage(HttpMethod.Post, "/Vault/Submit") { Content = form };
        req.Headers.Add("RequestVerificationToken", token!);
        var post = await client.SendAsync(req);
        Assert.That(post.StatusCode, Is.EqualTo(HttpStatusCode.OK).Or.EqualTo(HttpStatusCode.Redirect),
            $"Submit should accept the payload; got {post.StatusCode}");

        // Read the rendered messages page.
        var html = await client.GetStringAsync("/Vault/Messages");

        // The raw <script> tag must NEVER appear as executable markup.
        Assert.That(html, Does.Not.Contain("<script>alert"),
            "Raw <script> markup leaked into the page — XSS vulnerability!");

        // It must appear HTML-encoded instead.
        Assert.That(html.Contains("&lt;script&gt;") || html.Contains("&lt;script"),
            "Expected the payload to be HTML-encoded on output.");
    }
}
