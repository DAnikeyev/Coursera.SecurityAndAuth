using System.Net;
using System.Net.Http.Headers;
using System.Text.RegularExpressions;

namespace SafeVault.Tests;

/// <summary>
/// Helpers for driving the real login form, including the antiforgery token,
/// against the in-process test server.
/// </summary>
public static class HttpAuthHelper
{
    private static readonly Regex AntiforgeryRegex =
        new(@"name=""__RequestVerificationToken""[^>]*value=""([^""]+)""", RegexOptions.Compiled);

    /// <summary>
    /// Posts the login form with the supplied credentials. Returns the HTTP
    /// status code of the response (redirects are NOT followed).
    /// </summary>
    public static async Task<HttpStatusCode> LoginAsync(
        this HttpClient client, string email, string password)
    {
        // 1. GET the login page to obtain the antiforgery token + cookie.
        var get = await client.GetAsync("/Account/Login");
        get.EnsureSuccessStatusCode();
        var html = await get.Content.ReadAsStringAsync();
        var match = AntiforgeryRegex.Match(html);
        if (!match.Success)
        {
            throw new InvalidOperationException("Could not find antiforgery token on login page.");
        }

        var token = match.Groups[1].Value;

        // 2. POST the credentials with the token and the same cookie container.
        var form = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["Email"] = email,
            ["Password"] = password,
            ["RememberMe"] = "false",
            ["__RequestVerificationToken"] = token
        });

        var post = await client.PostAsync("/Account/Login", form);
        return post.StatusCode;
    }
}
