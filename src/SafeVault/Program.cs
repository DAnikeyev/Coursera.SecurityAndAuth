using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using SafeVault.Data;
using SafeVault.Models;
using SafeVault.Security;
using SafeVault.Services;

var builder = WebApplication.CreateBuilder(args);

// ---- Database (SQLite) -------------------------------------------------------
// The connection string points at a local SQLite file so the app is fully
// runnable without an external server. Entity Framework Core is used for the
// Identity schema; the raw parameterized queries live in UserRepository.
builder.Services.AddDbContext<ApplicationDbContext>(options =>
    options.UseSqlite(builder.Configuration.GetConnectionString("DefaultConnection")
                      ?? "Data Source=safevault.db"));

// ---- ASP.NET Core Identity ---------------------------------------------------
// Identity gives us secure user storage, password hashing, lockout, and roles.
// We replace the default PBKDF2 hasher with a bcrypt-based one to demonstrate
// an industry-standard slow hashing algorithm (Activity 2 requirement).
builder.Services
    .AddIdentity<ApplicationUser, IdentityRole>(options =>
    {
        // Strong password policy.
        options.Password.RequiredLength = 8;
        options.Password.RequireDigit = true;
        options.Password.RequireUppercase = true;
        options.Password.RequireNonAlphanumeric = true;
        options.Lockout.MaxFailedAccessAttempts = 5;
        options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(15);
        options.User.RequireUniqueEmail = true;
    })
    .AddEntityFrameworkStores<ApplicationDbContext>()
    .AddDefaultTokenProviders();

// Plug in bcrypt password hashing (replaces Identity's default PBKDF2 hasher).
builder.Services.AddScoped<IPasswordHasher<ApplicationUser>, BcryptPasswordHasher<ApplicationUser>>();

builder.Services.AddControllersWithViews();

// Custom application services.
builder.Services.AddScoped<IUserRepository, UserRepository>();
builder.Services.AddSingleton<InputValidator>();

// Cookie-based authentication settings.
builder.Services.ConfigureApplicationCookie(options =>
{
    options.LoginPath = "/Account/Login";
    options.AccessDeniedPath = "/Account/AccessDenied";
    options.ExpireTimeSpan = TimeSpan.FromMinutes(30);
    options.SlidingExpiration = true;
});

var app = builder.Build();

// ---- Create the database and seed roles / demo users ------------------------
using (var scope = app.Services.CreateScope())
{
    var db = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();
    db.Database.EnsureCreated();
    await DbInitializer.SeedAsync(scope.ServiceProvider);
}

// ---- Request pipeline --------------------------------------------------------
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Home/Error");
    app.UseHsts();
}

app.UseHttpsRedirection();
app.UseStaticFiles();

app.UseRouting();

// Order matters: Authentication must run before Authorization.
app.UseAuthentication();
app.UseAuthorization();

// Add a strict Content-Security-Policy / X-Content-Type-Options header to harden
// against XSS and content-type sniffing (defense-in-depth for Activity 3).
app.Use(async (context, next) =>
{
    context.Response.Headers["X-Content-Type-Options"] = "nosniff";
    context.Response.Headers["X-Frame-Options"] = "DENY";
    context.Response.Headers["Content-Security-Policy"] =
        "default-src 'self'; object-src 'none'; frame-ancestors 'none'";
    await next();
});

app.MapControllerRoute(
    name: "default",
    pattern: "{controller=Home}/{action=Index}/{id?}");

app.Run();

// Expose the entry point to the test host (WebApplicationFactory).
public partial class Program { }
