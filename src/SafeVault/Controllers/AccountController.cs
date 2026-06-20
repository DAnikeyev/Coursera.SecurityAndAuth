using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using SafeVault.Data;
using SafeVault.Models;
using SafeVault.Services;

namespace SafeVault.Controllers;

public class AccountController : Controller
{
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly SignInManager<ApplicationUser> _signInManager;
    private readonly InputValidator _validator;

    public AccountController(
        UserManager<ApplicationUser> userManager,
        SignInManager<ApplicationUser> signInManager,
        InputValidator validator)
    {
        _userManager = userManager;
        _signInManager = signInManager;
        _validator = validator;
    }

    // ---------------- Registration ----------------

    [HttpGet]
    public IActionResult Register() => View();

    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Register(RegisterViewModel model)
    {
        // Validate username/email through our centralised sanitizer before
        // anything touches the database (Activity 1).
        var usernameCheck = _validator.ValidateUsername(model.Username);
        var emailCheck = _validator.ValidateEmail(model.Email);
        if (!usernameCheck.IsValid)
        {
            ModelState.AddModelError(nameof(model.Username), usernameCheck.Error!);
        }
        if (!emailCheck.IsValid)
        {
            ModelState.AddModelError(nameof(model.Email), emailCheck.Error!);
        }

        if (!ModelState.IsValid)
        {
            return View(model);
        }

        var user = new ApplicationUser
        {
            UserName = emailCheck.Sanitized,
            Email = emailCheck.Sanitized,
            DisplayName = usernameCheck.Sanitized,
            EmailConfirmed = true
        };

        // UserManager.CreateAsync hashes the password via the configured
        // BcryptPasswordHasher and stores the user with parameterized EF Core.
        var result = await _userManager.CreateAsync(user, model.Password);
        if (!result.Succeeded)
        {
            foreach (var error in result.Errors)
            {
                ModelState.AddModelError(string.Empty, error.Description);
            }
            return View(model);
        }

        // New self-service registrations are plain users. Admins are seeded.
        await _userManager.AddToRoleAsync(user, DbInitializer.UserRole);

        await _signInManager.SignInAsync(user, isPersistent: false);
        return RedirectToAction("Index", "Home");
    }

    // ---------------- Login ----------------

    [HttpGet]
    public IActionResult Login(string? returnUrl = null)
    {
        ViewData["ReturnUrl"] = returnUrl;
        return View();
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Login(LoginViewModel model, string? returnUrl = null)
    {
        var emailCheck = _validator.ValidateEmail(model.Email);
        if (!emailCheck.IsValid || !ModelState.IsValid)
        {
            ModelState.AddModelError(string.Empty, "Invalid login attempt.");
            return View(model);
        }

        var user = await _userManager.FindByEmailAsync(emailCheck.Sanitized);
        if (user is null)
        {
            // Same message for "no such user" and "wrong password" to avoid
            // user enumeration via distinct error messages.
            ModelState.AddModelError(string.Empty, "Invalid login attempt.");
            return View(model);
        }

        // Password verification uses the bcrypt hasher; lockout is enforced.
        var result = await _signInManager.PasswordSignInAsync(
            user.UserName!, model.Password, model.RememberMe, lockoutOnFailure: true);

        if (result.Succeeded)
        {
            return RedirectToLocal(returnUrl);
        }

        if (result.IsLockedOut)
        {
            return View("Lockout");
        }

        ModelState.AddModelError(string.Empty, "Invalid login attempt.");
        return View(model);
    }

    // ---------------- Logout ----------------

    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Logout()
    {
        await _signInManager.SignOutAsync();
        return RedirectToAction("Index", "Home");
    }

    [HttpGet]
    public IActionResult AccessDenied() => View();

    private IActionResult RedirectToLocal(string? returnUrl)
    {
        if (!string.IsNullOrEmpty(returnUrl) && Url.IsLocalUrl(returnUrl))
        {
            return Redirect(returnUrl);
        }
        return RedirectToAction("Index", "Home");
    }
}
