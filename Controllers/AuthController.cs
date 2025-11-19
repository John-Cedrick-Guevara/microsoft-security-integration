using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Mvc;
using Secure.Authorization;
using Secure.Models;
using System.Security.Claims;
using AuthService = Secure.Services.IAuthenticationService;

namespace Secure.Controllers
{
    /// <summary>
    /// Controller handling authentication and authorization
    /// SECURITY: Implements secure login, logout, and role-based access
    /// </summary>
    public class AuthController : Controller
    {
        private readonly AuthService _authService;
        private readonly ILogger<AuthController> _logger;

        public AuthController(AuthService authService, ILogger<AuthController> logger)
        {
            _authService = authService;
            _logger = logger;
        }

        /// <summary>
        /// Display login page
        /// </summary>
        [HttpGet]
        public IActionResult Login(string? returnUrl = null)
        {
            ViewData["ReturnUrl"] = returnUrl;
            return View();
        }

        /// <summary>
        /// Process login attempt
        /// SECURITY: Validates credentials and creates authentication cookie
        /// </summary>
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Login(LoginViewModel model, string? returnUrl = null)
        {
            ViewData["ReturnUrl"] = returnUrl;

            if (!ModelState.IsValid)
            {
                return View(model);
            }

            // SECURITY: Authenticate user
            var result = await _authService.AuthenticateAsync(model.Username, model.Password);

            if (!result.Success)
            {
                if (result.IsLockedOut)
                {
                    ModelState.AddModelError(string.Empty, result.Message);
                    return View(model);
                }

                if (result.RemainingAttempts > 0 && result.RemainingAttempts <= 3)
                {
                    ModelState.AddModelError(string.Empty, 
                        $"Invalid username or password. {result.RemainingAttempts} attempts remaining.");
                }
                else
                {
                    ModelState.AddModelError(string.Empty, "Invalid username or password.");
                }

                _logger.LogWarning("Failed login attempt for username: {Username}", model.Username);
                return View(model);
            }

            // SECURITY: Create authentication claims
            var claims = new List<Claim>
            {
                new Claim(ClaimTypes.NameIdentifier, result.User!.UserID.ToString()),
                new Claim(ClaimTypes.Name, result.User.Username),
                new Claim(ClaimTypes.Email, result.User.Email),
                new Claim(ClaimTypes.Role, result.User.Role.ToString()),
                new Claim("UserRole", result.User.Role.ToString()) // Additional role claim
            };

            // SECURITY: Create authentication cookie with secure settings
            var claimsIdentity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);
            var authProperties = new AuthenticationProperties
            {
                IsPersistent = model.RememberMe,
                ExpiresUtc = model.RememberMe 
                    ? DateTimeOffset.UtcNow.AddDays(30) 
                    : DateTimeOffset.UtcNow.AddHours(2),
                AllowRefresh = true
            };

            await HttpContext.SignInAsync(
                CookieAuthenticationDefaults.AuthenticationScheme,
                new ClaimsPrincipal(claimsIdentity),
                authProperties);

            _logger.LogInformation("User logged in successfully: {Username} with role {Role}", 
                result.User.Username, result.User.Role);

            // Redirect based on return URL or role
            if (!string.IsNullOrEmpty(returnUrl) && Url.IsLocalUrl(returnUrl))
            {
                return Redirect(returnUrl);
            }

            // Redirect admin users to admin dashboard
            if (result.User.Role == UserRole.Admin)
            {
                return RedirectToAction("Index", "Admin");
            }

            return RedirectToAction("Index", "Home");
        }

        /// <summary>
        /// Display registration page
        /// </summary>
        [HttpGet]
        public IActionResult Register()
        {
            return View();
        }

        /// <summary>
        /// Process registration
        /// SECURITY: Validates input and creates user with hashed password
        /// </summary>
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Register(RegisterViewModel model)
        {
            if (!ModelState.IsValid)
            {
                return View(model);
            }

            // SECURITY: Register user with hashed password
            var result = await _authService.RegisterAsync(
                model.Username, 
                model.Email, 
                model.Password, 
                UserRole.User); // New registrations default to User role

            if (!result.Success)
            {
                ModelState.AddModelError(string.Empty, result.Message);
                return View(model);
            }

            _logger.LogInformation("New user registered: {Username}", model.Username);

            TempData["SuccessMessage"] = "Registration successful! Please log in.";
            return RedirectToAction("Login");
        }

        /// <summary>
        /// Logout current user
        /// SECURITY: Clears authentication cookie
        /// </summary>
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Logout()
        {
            var username = User.Identity?.Name;
            
            await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
            
            _logger.LogInformation("User logged out: {Username}", username);

            return RedirectToAction("Login");
        }

        /// <summary>
        /// Access denied page
        /// </summary>
        [HttpGet]
        public IActionResult AccessDenied()
        {
            return View();
        }

        /// <summary>
        /// Test page for authenticated users
        /// SECURITY: Requires authentication
        /// </summary>
        [RequireAuthentication]
        [HttpGet]
        public IActionResult Profile()
        {
            var userId = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
            var username = User.FindFirst(ClaimTypes.Name)?.Value;
            var email = User.FindFirst(ClaimTypes.Email)?.Value;
            var role = User.FindFirst(ClaimTypes.Role)?.Value;

            ViewData["UserId"] = userId;
            ViewData["Username"] = username;
            ViewData["Email"] = email;
            ViewData["Role"] = role;

            return View();
        }
    }
}
