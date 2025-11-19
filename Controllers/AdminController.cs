using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Secure.Authorization;
using Secure.Data;
using Secure.Models;
using System.Security.Claims;
using AuthService = Secure.Services.IAuthenticationService;

namespace Secure.Controllers
{
    /// <summary>
    /// Admin dashboard controller
    /// SECURITY: Only accessible by users with Admin role
    /// </summary>
    [AdminOnly] // SECURITY: Restricts access to Admin role only
    public class AdminController : Controller
    {
        private readonly ApplicationDbContext _context;
        private readonly AuthService _authService;
        private readonly ILogger<AdminController> _logger;

        public AdminController(
            ApplicationDbContext context,
            AuthService authService,
            ILogger<AdminController> logger)
        {
            _context = context;
            _authService = authService;
            _logger = logger;
        }

        /// <summary>
        /// Admin dashboard home page
        /// SECURITY: Only accessible by administrators
        /// </summary>
        public async Task<IActionResult> Index()
        {
            var currentUsername = User.FindFirst(ClaimTypes.Name)?.Value;
            _logger.LogInformation("Admin {Username} accessed admin dashboard", currentUsername);

            // Get statistics
            var totalUsers = await _context.Users.CountAsync();
            var activeUsers = await _context.Users.CountAsync(u => u.IsActive);
            var lockedUsers = await _context.Users.CountAsync(u => u.LockoutEnd != null && u.LockoutEnd > DateTime.UtcNow);
            var adminUsers = await _context.Users.CountAsync(u => u.Role == UserRole.Admin);

            ViewData["TotalUsers"] = totalUsers;
            ViewData["ActiveUsers"] = activeUsers;
            ViewData["LockedUsers"] = lockedUsers;
            ViewData["AdminUsers"] = adminUsers;

            return View();
        }

        /// <summary>
        /// List all users
        /// SECURITY: Only accessible by administrators
        /// </summary>
        public async Task<IActionResult> Users()
        {
            var users = await _context.Users
                .OrderByDescending(u => u.CreatedAt)
                .ToListAsync();

            return View(users);
        }

        /// <summary>
        /// Unlock a user account
        /// SECURITY: Only accessible by administrators
        /// </summary>
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> UnlockUser(int userId)
        {
            var result = await _authService.UnlockAccountAsync(userId);
            
            if (result)
            {
                var adminUsername = User.FindFirst(ClaimTypes.Name)?.Value;
                _logger.LogInformation("Admin {AdminUsername} unlocked user account {UserId}", 
                    adminUsername, userId);
                
                TempData["SuccessMessage"] = "User account unlocked successfully";
            }
            else
            {
                TempData["ErrorMessage"] = "Failed to unlock user account";
            }

            return RedirectToAction("Users");
        }

        /// <summary>
        /// Change user role
        /// SECURITY: Only accessible by administrators
        /// </summary>
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> ChangeRole(int userId, UserRole newRole)
        {
            // SECURITY: Prevent changing own role
            var currentUserId = int.Parse(User.FindFirst(ClaimTypes.NameIdentifier)?.Value ?? "0");
            if (userId == currentUserId)
            {
                TempData["ErrorMessage"] = "Cannot change your own role";
                return RedirectToAction("Users");
            }

            var result = await _authService.UpdateUserRoleAsync(userId, newRole);
            
            if (result)
            {
                var adminUsername = User.FindFirst(ClaimTypes.Name)?.Value;
                _logger.LogInformation("Admin {AdminUsername} changed role for user {UserId} to {NewRole}", 
                    adminUsername, userId, newRole);
                
                TempData["SuccessMessage"] = $"User role changed to {newRole} successfully";
            }
            else
            {
                TempData["ErrorMessage"] = "Failed to change user role";
            }

            return RedirectToAction("Users");
        }

        /// <summary>
        /// Toggle user active status
        /// SECURITY: Only accessible by administrators
        /// </summary>
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> ToggleActiveStatus(int userId)
        {
            // SECURITY: Prevent deactivating own account
            var currentUserId = int.Parse(User.FindFirst(ClaimTypes.NameIdentifier)?.Value ?? "0");
            if (userId == currentUserId)
            {
                TempData["ErrorMessage"] = "Cannot deactivate your own account";
                return RedirectToAction("Users");
            }

            var user = await _context.Users.FindAsync(userId);
            if (user == null)
            {
                TempData["ErrorMessage"] = "User not found";
                return RedirectToAction("Users");
            }

            user.IsActive = !user.IsActive;
            await _context.SaveChangesAsync();

            var adminUsername = User.FindFirst(ClaimTypes.Name)?.Value;
            _logger.LogInformation("Admin {AdminUsername} {Action} user {UserId}", 
                adminUsername, user.IsActive ? "activated" : "deactivated", userId);

            TempData["SuccessMessage"] = $"User account {(user.IsActive ? "activated" : "deactivated")} successfully";
            return RedirectToAction("Users");
        }

        /// <summary>
        /// View recent login activity
        /// SECURITY: Only accessible by administrators
        /// </summary>
        public async Task<IActionResult> Activity()
        {
            var recentLogins = await _context.Users
                .Where(u => u.LastLogin != null)
                .OrderByDescending(u => u.LastLogin)
                .Take(50)
                .ToListAsync();

            return View(recentLogins);
        }
    }
}
