using SafeVault.Services;

namespace SafeVault.Tests;

/// <summary>
/// Activity 1 — input validation. The InputValidator must reject malicious
/// SQL-injection and XSS payloads in structured fields and neutralize them in
/// free-form text.
/// </summary>
[TestFixture]
public class InputValidationTests
{
    private readonly InputValidator _validator = new();

    // ---- SQL injection payloads must be rejected in the username field ----
    [TestCase("' OR '1'='1")]
    [TestCase("admin'--")]
    [TestCase("x'; DROP TABLE Users;--")]
    [TestCase("1; UNION SELECT * FROM AspNetUsers")]
    public void Username_RejectsSqlInjectionPayloads(string payload)
    {
        var result = _validator.ValidateUsername(payload);
        Assert.Multiple(() =>
        {
            Assert.That(result.IsValid, Is.False, $"Payload should be rejected: {payload}");
            Assert.That(result.Error, Is.Not.Null);
        });
    }

    // ---- XSS payloads must be rejected in the username field ----
    [TestCase("<script>alert(1)</script>")]
    [TestCase("<img src=x onerror=alert(1)>")]
    [TestCase("javascript:alert(document.cookie)")]
    [TestCase("<iframe src=evil.com></iframe>")]
    public void Username_RejectsXssPayloads(string payload)
    {
        var result = _validator.ValidateUsername(payload);
        Assert.That(result.IsValid, Is.False, $"Payload should be rejected: {payload}");
    }

    [Test]
    public void Username_AcceptsValidValue()
    {
        var result = _validator.ValidateUsername("alice_99");
        Assert.Multiple(() =>
        {
            Assert.That(result.IsValid, Is.True);
            Assert.That(result.Sanitized, Is.EqualTo("alice_99"));
        });
    }

    [Test]
    public void Username_RejectsEmptyAndTooLong()
    {
        Assert.That(_validator.ValidateUsername("").IsValid, Is.False);
        Assert.That(_validator.ValidateUsername("   ").IsValid, Is.False);
        var tooLong = new string('a', 51);
        Assert.That(_validator.ValidateUsername(tooLong).IsValid, Is.False);
    }

    [Test]
    public void Email_AcceptsValid_AndRejectsMalformed()
    {
        Assert.That(_validator.ValidateEmail("user@example.com").IsValid, Is.True);
        Assert.That(_validator.ValidateEmail("not-an-email").IsValid, Is.False);
        Assert.That(_validator.ValidateEmail("@example.com").IsValid, Is.False);
    }

    [Test]
    public void Email_RejectsInjectionPayload()
    {
        var result = _validator.ValidateEmail("a@b.com' OR '1'='1");
        Assert.That(result.IsValid, Is.False);
    }

    // ---- Free-form text: input sanitization strips control bytes.
    //      (Output encoding is verified end-to-end in XssTests.) ----
    [Test]
    public void FreeText_StripsNullAndControlBytes()
    {
        Assert.That(_validator.SanitizeFreeText("ab\0cd"), Is.EqualTo("abcd"));
        Assert.That(_validator.SanitizeFreeText("a\rb"), Is.EqualTo("ab"));
    }

    [Test]
    public void FreeText_PreservesLegitimateAngleBrackets()
    {
        // We do NOT mangle legitimate content on input; the value is escaped on
        // output by Razor instead.
        Assert.That(_validator.SanitizeFreeText("1 < 2 && 3 > 2"), Is.EqualTo("1 < 2 && 3 > 2"));
    }

    [Test]
    public void ContainsSuspiciousContent_DetectsKnownSignatures()
    {
        Assert.That(InputValidator.ContainsSuspiciousContent("OR 1=1"), Is.True);
        Assert.That(InputValidator.ContainsSuspiciousContent("<script>"), Is.True);
        Assert.That(InputValidator.ContainsSuspiciousContent("hello world"), Is.False);
    }
}
