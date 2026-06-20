using SafeVault.Models;

namespace SafeVault.Services;

/// <summary>
/// Data access for users and messages. Every method MUST use parameterized
/// queries — never string concatenation — so user-supplied data can never be
/// interpreted as SQL. This is the primary SQL injection defense.
/// </summary>
public interface IUserRepository
{
    /// <summary>Look up a user by their email using a parameterized query.</summary>
    Task<ApplicationUser?> GetByEmailAsync(string email);

    /// <summary>
    /// Search users whose username or email contains the keyword. Uses a
    /// parameterized LIKE clause.
    /// </summary>
    Task<IReadOnlyList<ApplicationUser>> SearchAsync(string keyword);

    /// <summary>
    /// Store a user message with a parameterized INSERT.
    /// </summary>
    Task AddMessageAsync(string username, string content);

    /// <summary>Return all stored messages, newest first.</summary>
    Task<IReadOnlyList<UserMessage>> GetMessagesAsync();
}
