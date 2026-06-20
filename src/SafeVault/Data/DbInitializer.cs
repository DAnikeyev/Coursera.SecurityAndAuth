using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;
using SafeVault.Models;

namespace SafeVault.Data;

/// <summary>
/// Seeds the database with the application's roles and a couple of demo users
/// so authentication/authorization can be exercised immediately.
/// </summary>
public static class DbInitializer
{
    public const string AdminRole = "Admin";
    public const string UserRole = "User";

    public static async Task SeedAsync(IServiceProvider services)
    {
        var roleManager = services.GetRequiredService<RoleManager<IdentityRole>>();
        var userManager = services.GetRequiredService<UserManager<ApplicationUser>>();

    await EnsureRoleAsync(roleManager, AdminRole);
    await EnsureRoleAsync(roleManager, UserRole);

        await EnsureUserAsync(userManager, "admin@safevault.local", "Admin#1234", AdminRole, "Site Administrator");
        await EnsureUserAsync(userManager, "user@safevault.local", "User#1234", UserRole, "Standard User");
    }

    private static async Task EnsureRoleAsync(RoleManager<IdentityRole> roleManager, string role)
    {
        if (!await roleManager.RoleExistsAsync(role))
        {
            await roleManager.CreateAsync(new IdentityRole(role));
        }
    }

    private static async Task EnsureUserAsync(
        UserManager<ApplicationUser> userManager,
        string email,
        string password,
        string role,
        string displayName)
    {
        if (await userManager.FindByEmailAsync(email) is not null)
        {
            return;
        }

        var user = new ApplicationUser
        {
            UserName = email,
            Email = email,
            EmailConfirmed = true,
            DisplayName = displayName
        };

        var result = await userManager.CreateAsync(user, password);
        if (result.Succeeded)
        {
            await userManager.AddToRoleAsync(user, role);
        }
    }
}
