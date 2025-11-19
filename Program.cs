using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.EntityFrameworkCore;
using Secure.Data;
using Secure.Services;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.AddControllersWithViews();

// SECURITY: Configure database with connection string
// For production, use secure connection strings from Azure Key Vault or environment variables
builder.Services.AddDbContext<ApplicationDbContext>(options =>
{
    // Use in-memory database for development/testing
    // For production, replace with: options.UseSqlServer(builder.Configuration.GetConnectionString("DefaultConnection"));
    options.UseInMemoryDatabase("SafeVaultDb");
});

// SECURITY: Register services
builder.Services.AddScoped<IUserService, UserService>();
builder.Services.AddScoped<IPasswordHashingService, PasswordHashingService>();
builder.Services.AddScoped<IAuthenticationService, AuthenticationService>();

// SECURITY: Configure cookie-based authentication
builder.Services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
    .AddCookie(options =>
    {
        options.LoginPath = "/Auth/Login";
        options.LogoutPath = "/Auth/Logout";
        options.AccessDeniedPath = "/Auth/AccessDenied";
        options.ExpireTimeSpan = TimeSpan.FromHours(2);
        options.SlidingExpiration = true;
        
        // SECURITY: Secure cookie settings
        options.Cookie.HttpOnly = true;
        options.Cookie.SecurePolicy = CookieSecurePolicy.Always; // Require HTTPS
        options.Cookie.SameSite = SameSiteMode.Strict; // CSRF protection
        options.Cookie.Name = "SafeVault.Auth";
    });

// SECURITY: Add authorization
builder.Services.AddAuthorization();

// SECURITY: Add anti-forgery token configuration
builder.Services.AddAntiforgery(options =>
{
    options.HeaderName = "X-CSRF-TOKEN";
    options.Cookie.Name = "CSRF-TOKEN";
    options.Cookie.HttpOnly = true;
    options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
    options.Cookie.SameSite = SameSiteMode.Strict;
});

// SECURITY: Configure security headers
builder.Services.AddHsts(options =>
{
    options.MaxAge = TimeSpan.FromDays(365);
    options.IncludeSubDomains = true;
    options.Preload = true;
});

var app = builder.Build();

// SECURITY: Initialize database with seed data
using (var scope = app.Services.CreateScope())
{
    var context = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();
    context.Database.EnsureCreated(); // Creates database and applies seed data
}

// Configure the HTTP request pipeline.
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Home/Error");
    // SECURITY: Enable HSTS (HTTP Strict Transport Security)
    app.UseHsts();
}

// SECURITY: Enforce HTTPS redirection
app.UseHttpsRedirection();

// SECURITY: Add security headers middleware
app.Use(async (context, next) =>
{
    // XSS Protection
    context.Response.Headers.Append("X-Content-Type-Options", "nosniff");
    context.Response.Headers.Append("X-Frame-Options", "DENY");
    context.Response.Headers.Append("X-XSS-Protection", "1; mode=block");
    
    // Content Security Policy - prevents XSS by controlling resource loading
    context.Response.Headers.Append("Content-Security-Policy", 
        "default-src 'self'; " +
        "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; " +
        "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; " +
        "img-src 'self' data:; " +
        "font-src 'self' https://cdn.jsdelivr.net; " +
        "connect-src 'self'; " +
        "frame-ancestors 'none';");
    
    // Referrer Policy
    context.Response.Headers.Append("Referrer-Policy", "strict-origin-when-cross-origin");
    
    // Permissions Policy
    context.Response.Headers.Append("Permissions-Policy", 
        "geolocation=(), microphone=(), camera=()");

    await next();
});

app.UseRouting();

// SECURITY: Enable authentication and authorization middleware
app.UseAuthentication(); // Must come before UseAuthorization
app.UseAuthorization();

app.MapStaticAssets();

app.MapControllerRoute(
    name: "default",
    pattern: "{controller=Home}/{action=Index}/{id?}")
    .WithStaticAssets();

app.Run();
