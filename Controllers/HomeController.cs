using System.Diagnostics;
using Microsoft.AspNetCore.Mvc;
using Secure.Models;
using Secure.Services;
using Secure.Utilities;

namespace Secure.Controllers;

/// <summary>
/// Secure controller implementing XSS and SQL injection protection
/// </summary>
public class HomeController : Controller
{
    private readonly IUserService _userService;
    private readonly ILogger<HomeController> _logger;

    public HomeController(IUserService userService, ILogger<HomeController> logger)
    {
        _userService = userService;
        _logger = logger;
    }

    /// <summary>
    /// Display the secure registration form
    /// </summary>
    public IActionResult Index()
    {
        return View(new UserRegistrationViewModel());
    }

    /// <summary>
    /// Handles secure user registration with comprehensive validation
    /// Prevents SQL injection through parameterized queries
    /// Prevents XSS through input sanitization and output encoding
    /// </summary>
    [HttpPost]
    [ValidateAntiForgeryToken] // SECURITY: Protects against CSRF attacks
    public async Task<IActionResult> Register(UserRegistrationViewModel model)
    {
        try
        {
            // SECURITY: Server-side model validation (first line of defense)
            if (!ModelState.IsValid)
            {
                _logger.LogWarning("Invalid model state for registration");
                TempData["ErrorMessage"] = "Please correct the validation errors and try again.";
                return View("Index", model);
            }

            // SECURITY: Additional validation layer
            if (!InputSanitizer.IsValidUsername(model.Username))
            {
                _logger.LogWarning("Invalid username format: {Username}", model.Username);
                TempData["ErrorMessage"] = "Username must be 3-50 characters and contain only letters, numbers, and underscores.";
                return View("Index", model);
            }

            if (!InputSanitizer.IsValidEmail(model.Email))
            {
                _logger.LogWarning("Invalid email format: {Email}", model.Email);
                TempData["ErrorMessage"] = "Please provide a valid email address.";
                return View("Index", model);
            }

            // SECURITY: Check for SQL injection attempts
            if (InputSanitizer.ContainsSqlInjectionPatterns(model.Username) || 
                InputSanitizer.ContainsSqlInjectionPatterns(model.Email))
            {
                _logger.LogWarning("SQL injection attempt detected. Username: {Username}, Email: {Email}", 
                    model.Username, model.Email);
                TempData["ErrorMessage"] = "Invalid input detected. SQL commands are not allowed.";
                return View("Index", model);
            }

            // SECURITY: Check for XSS attempts
            if (InputSanitizer.ContainsXssPatterns(model.Username) || 
                InputSanitizer.ContainsXssPatterns(model.Email))
            {
                _logger.LogWarning("XSS attempt detected. Username: {Username}, Email: {Email}", 
                    model.Username, model.Email);
                TempData["ErrorMessage"] = "Invalid input detected. Script tags and HTML are not allowed.";
                return View("Index", model);
            }

            // SECURITY: Create user with sanitized inputs using parameterized queries
            var user = await _userService.CreateUserAsync(model.Username, model.Email);

            if (user != null)
            {
                _logger.LogInformation("User registered successfully: {UserId}", user.UserID);
                TempData["SuccessMessage"] = $"Registration successful! Welcome, {user.Username}!";
                
                // Clear the form
                return RedirectToAction("Index");
            }
            else
            {
                _logger.LogWarning("User registration failed for username: {Username}", model.Username);
                TempData["ErrorMessage"] = "Registration failed. Username or email may already be in use.";
                return View("Index", model);
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error during user registration");
            TempData["ErrorMessage"] = "An error occurred during registration. Please try again.";
            return View("Index", model);
        }
    }

    /// <summary>
    /// API endpoint to get recent users (with XSS protection via JSON serialization)
    /// </summary>
    [HttpGet]
    public async Task<IActionResult> GetRecentUsers()
    {
        try
        {
            // SECURITY: Retrieve users using parameterized queries
            var users = await _userService.GetAllUsersAsync(pageNumber: 1, pageSize: 5);

            // SECURITY: Data is automatically JSON-encoded, preventing XSS
            // Additionally, data was sanitized during storage
            var result = users.Select(u => new
            {
                userId = u.UserID,
                username = u.Username, // Already sanitized in database
                email = u.Email // Already sanitized in database
            }).ToList();

            return Json(result);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error retrieving recent users");
            return Json(new List<object>());
        }
    }

    /// <summary>
    /// Display all registered users securely
    /// </summary>
    [HttpGet]
    public async Task<IActionResult> Users(int page = 1)
    {
        try
        {
            // SECURITY: Validate pagination parameter
            if (page < 1) page = 1;

            // SECURITY: Retrieve users using parameterized queries
            var users = await _userService.GetAllUsersAsync(pageNumber: page, pageSize: 10);

            // SECURITY: Data is sanitized and will be HTML-encoded in the view
            return View(users);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error retrieving users list");
            return View(new List<User>());
        }
    }

    public IActionResult Privacy()
    {
        return View();
    }

    [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
    public IActionResult Error()
    {
        return View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
    }
}
