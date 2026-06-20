namespace SafeVault.Models;

/// <summary>
/// A piece of user-generated content. The <see cref="Content"/> field is the
/// primary surface for XSS testing: it must never be rendered as raw HTML.
/// </summary>
public class UserMessage
{
    public int Id { get; set; }
    public string Username { get; set; } = string.Empty;
    public string Content { get; set; } = string.Empty;
    public DateTime CreatedAtUtc { get; set; } = DateTime.UtcNow;
}
