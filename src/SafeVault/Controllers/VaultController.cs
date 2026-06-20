using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using SafeVault.Models;
using SafeVault.Services;

namespace SafeVault.Controllers;

/// <summary>
/// Handles the SafeVault "web form" (username + email + optional message).
/// Demonstrates Activity 1's input validation and parameterized persistence,
/// and Activity 3's safe output handling of user-generated content.
/// </summary>
[Authorize]
public class VaultController : Controller
{
    private readonly InputValidator _validator;
    private readonly IUserRepository _repo;

    public VaultController(InputValidator validator, IUserRepository repo)
    {
        _validator = validator;
        _repo = repo;
    }

    [HttpGet]
    public IActionResult Submit() => View();

    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Submit(SubmitViewModel model)
    {
        // Validate structured fields (reject malicious input at the boundary).
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

        // Free-form text is sanitized (HTML-encoded) so script can never execute,
        // then stored via a parameterized INSERT.
        var sanitizedMessage = _validator.SanitizeFreeText(model.Message);
        await _repo.AddMessageAsync(usernameCheck.Sanitized, sanitizedMessage);

        ViewBag.Success = "Your message was stored safely.";
        return View(new SubmitViewModel());
    }

    /// <summary>Renders stored messages. Razor HTML-encodes them on output.</summary>
    [HttpGet]
    public async Task<IActionResult> Messages()
    {
        var messages = await _repo.GetMessagesAsync();
        return View(messages);
    }
}
