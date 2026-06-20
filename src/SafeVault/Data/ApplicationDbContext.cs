using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using SafeVault.Models;

namespace SafeVault.Data;

/// <summary>
/// EF Core context that stores the ASP.NET Core Identity schema (users, roles,
/// claims, logins) in a SQLite database.
/// </summary>
public class ApplicationDbContext : IdentityDbContext<ApplicationUser>
{
    public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options)
        : base(options)
    {
    }

    /// <summary>
    /// User-submitted messages. Used to demonstrate safe handling and output
    /// encoding of user-generated content (XSS defense, Activity 3).
    /// </summary>
    public DbSet<UserMessage> UserMessages => Set<UserMessage>();

    protected override void OnModelCreating(ModelBuilder builder)
    {
        base.OnModelCreating(builder);

        builder.Entity<UserMessage>(entity =>
        {
            entity.HasKey(m => m.Id);
            entity.Property(m => m.Username).HasMaxLength(100).IsRequired();
            entity.Property(m => m.Content).IsRequired();
        });
    }
}
