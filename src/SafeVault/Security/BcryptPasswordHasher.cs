using Microsoft.AspNetCore.Identity;
using SafeVault.Models;

namespace SafeVault.Security;

/// <summary>
/// A bcrypt-backed <see cref="IPasswordHasher{TUser}"/>. ASP.NET Core Identity
/// ships with a secure PBKDF2 hasher by default; this implementation swaps in
/// bcrypt (work factor 12) to demonstrate a second industry-standard, slow,
/// salted password-hashing algorithm — satisfying the Activity 2 requirement
/// to hash passwords securely with a library such as bcrypt/Argon2.
///
/// Because we implement Identity's interface, every login, registration and
/// password change transparently uses bcrypt with no further wiring required.
/// </summary>
public sealed class BcryptPasswordHasher<TUser> : IPasswordHasher<TUser> where TUser : class
{
    private const int WorkFactor = 12;

    public string HashPassword(TUser user, string password)
    {
        if (password == null)
        {
            throw new ArgumentNullException(nameof(password));
        }

        return BCrypt.Net.BCrypt.HashPassword(password, WorkFactor);
    }

    public PasswordVerificationResult VerifyHashedPassword(TUser user, string hashedPassword, string providedPassword)
    {
        if (hashedPassword == null || providedPassword == null)
        {
            return PasswordVerificationResult.Failed;
        }

        try
        {
            return BCrypt.Net.BCrypt.Verify(providedPassword, hashedPassword)
                ? PasswordVerificationResult.Success
                : PasswordVerificationResult.Failed;
        }
        catch (BCrypt.Net.SaltParseException)
        {
            return PasswordVerificationResult.Failed;
        }
    }
}
