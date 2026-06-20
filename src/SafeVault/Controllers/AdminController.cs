using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using SafeVault.Data;
using SafeVault.Models;

namespace SafeVault.Controllers;

/// <summary>
/// Administrative tooling. Every action requires the authenticated user to be
/// in the <c>Admin</c> role — this is role-based access control (RBAC).
/// </summary>
[Authorize(Roles = "Admin")]
public class AdminController : Controller
{
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly RoleManager<IdentityRole> _roleManager;

    public AdminController(UserManager<ApplicationUser> userManager, RoleManager<IdentityRole> roleManager)
    {
        _userManager = userManager;
        _roleManager = roleManager;
    }

    /// <summary>The Admin Dashboard. Off-limits to everyone without the Admin role.</summary>
    public async Task<IActionResult> Dashboard()
    {
        var users = _userManager.Users.ToList();
        var rows = new List<UserWithRolesViewModel>(users.Count);
        foreach (var user in users)
        {
            rows.Add(new UserWithRolesViewModel
            {
                Id = user.Id,
                Email = user.Email ?? string.Empty,
                DisplayName = user.DisplayName,
                Roles = await _userManager.GetRolesAsync(user)
            });
        }

        ViewBag.Roles = _roleManager.Roles.Select(r => r.Name!).ToList();
        return View(rows);
    }
}

public class UserWithRolesViewModel
{
    public string Id { get; set; } = string.Empty;
    public string Email { get; set; } = string.Empty;
    public string? DisplayName { get; set; }
    public IList<string> Roles { get; set; } = new List<string>();
}
