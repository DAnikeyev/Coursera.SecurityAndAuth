using Microsoft.AspNetCore.Identity;

namespace SafeVault.Models;

/// <summary>
/// The application user. Extends ASP.NET Core Identity's <see cref="IdentityUser"/>
/// with a display name. Roles (Admin, User) are assigned through Identity's
/// role manager and authorize access to restricted features.
/// </summary>
public class ApplicationUser : IdentityUser
{
    /// <summary>Human-friendly name shown in the UI.</summary>
    public string DisplayName { get; set; } = string.Empty;

    /// <summary>When the account was created (UTC).</summary>
    public DateTime CreatedAtUtc { get; set; } = DateTime.UtcNow;
}
