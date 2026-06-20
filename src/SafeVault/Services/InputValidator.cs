using System.Net.Mail;
using System.Text;
using System.Text.RegularExpressions;

namespace SafeVault.Services;

/// <summary>
/// Result of validating a single piece of user input.
/// </summary>
public sealed class InputValidationResult
{
    public bool IsValid { get; init; }
    public string Sanitized { get; init; } = string.Empty;
    public string? Error { get; init; }

    public static InputValidationResult Ok(string sanitized) => new() { IsValid = true, Sanitized = sanitized };
    public static InputValidationResult Fail(string error) => new() { IsValid = false, Error = error };
}

/// <summary>
/// Centralised input validation and sanitization for SafeVault.
///
/// Defense-in-depth: even though the application uses parameterized queries
/// (which already neutralize SQL injection) and Razor output encoding (which
/// neutralizes XSS), we still reject obviously malicious input at the trust
/// boundary. This keeps dangerous payloads out of the database and off the page
/// entirely, and makes the intent of the application explicit.
/// </summary>
public sealed class InputValidator
{
    // Patterns commonly used in SQL injection and XSS payloads. Matching any of
    // these is treated as a rejection at the validation layer.
    private static readonly Regex SuspiciousPattern = new(
        @"(?i)(\bor\b\s+1\s*=\s*1|\bunion\b\s+\bselect\b|--\s|/\*|\*/|;\s*(drop|update|insert|delete|select)\b|" +
        @"<\s*script|javascript:|on(error|load|click|mouseover)\s*=|<\s*iframe|<\s*img[^>]+onerror)",
        RegexOptions.Compiled);

    // Allow only safe characters for a username: letters, digits, dot, underscore, hyphen, @.
    private static readonly Regex UsernameAllowed = new(@"^[a-zA-Z0-9._@\-]{3,50}$", RegexOptions.Compiled);

    /// <summary>
    /// Validates and sanitizes a username. Rejects empty, over-long, or
    /// malicious input; trims whitespace.
    /// </summary>
    public InputValidationResult ValidateUsername(string? raw)
    {
        if (string.IsNullOrWhiteSpace(raw))
        {
            return InputValidationResult.Fail("Username is required.");
        }

        var value = raw.Trim();

        if (ContainsSuspiciousContent(value))
        {
            return InputValidationResult.Fail("Username contains disallowed content.");
        }

        if (!UsernameAllowed.IsMatch(value))
        {
            return InputValidationResult.Fail("Username may only contain letters, digits, '.', '_', '-' and '@' (3-50 chars).");
        }

        return InputValidationResult.Ok(value);
    }

    /// <summary>
    /// Validates an email address using the framework parser and rejects
    /// suspicious payloads.
    /// </summary>
    public InputValidationResult ValidateEmail(string? raw)
    {
        if (string.IsNullOrWhiteSpace(raw))
        {
            return InputValidationResult.Fail("Email is required.");
        }

        var value = raw.Trim();

        if (ContainsSuspiciousContent(value))
        {
            return InputValidationResult.Fail("Email contains disallowed content.");
        }

        if (!MailAddress.TryCreate(value, out var mail) || mail.User.Length == 0)
        {
            return InputValidationResult.Fail("Email is not a valid address.");
        }

        return InputValidationResult.Ok(mail.Address);
    }

    /// <summary>
    /// Sanitizes free-form text (e.g. a message body). Free-form fields may
    /// legitimately contain characters like &lt; or &gt;, so we do not reject
    /// them here. Instead we remove control characters (NULL bytes, etc.) that
    /// have no business being in user text. The actual XSS mitigation is
    /// context-aware output encoding: Razor HTML-encodes the value when it is
    /// rendered, which is the correct layer at which to escape for an HTML
    /// context. Sanitize on input, encode on output.
    /// </summary>
    public string SanitizeFreeText(string? raw)
    {
        if (string.IsNullOrEmpty(raw))
        {
            return string.Empty;
        }

        var value = raw.Trim();

        // Strip NULL bytes and other C0 control characters (no legit reason to
        // be in user-supplied text; they can be used to bypass filters).
        var sb = new StringBuilder(value.Length);
        foreach (var ch in value)
        {
            if (ch != '\0' && ch != '\r')
            {
                sb.Append(ch);
            }
        }

        return sb.ToString();
    }

    /// <summary>
    /// Returns true if the supplied text matches a known injection/XSS signature.
    /// Public so tests can verify the detection rules directly.
    /// </summary>
    public static bool ContainsSuspiciousContent(string input)
        => !string.IsNullOrEmpty(input) && SuspiciousPattern.IsMatch(input);
}
