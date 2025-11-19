using Microsoft.EntityFrameworkCore;
using Secure.Data;
using Secure.Models;
using Secure.Utilities;

namespace Secure.Services
{
    /// <summary>
    /// Secure user service implementing parameterized queries to prevent SQL injection
    /// All database operations use Entity Framework Core with proper input validation
    /// </summary>
    public class UserService : IUserService
    {
        private readonly ApplicationDbContext _context;
        private readonly ILogger<UserService> _logger;

        public UserService(ApplicationDbContext context, ILogger<UserService> logger)
        {
            _context = context;
            _logger = logger;
        }

        /// <summary>
        /// Creates a new user with comprehensive input validation and sanitization
        /// Uses parameterized queries via Entity Framework to prevent SQL injection
        /// </summary>
        /// <param name="username">Username (validated and sanitized)</param>
        /// <param name="email">Email address (validated and sanitized)</param>
        /// <returns>Created user or null if validation fails</returns>
        public async Task<User?> CreateUserAsync(string username, string email)
        {
            try
            {
                // SECURITY: Validate inputs before processing
                if (!InputSanitizer.IsValidUsername(username))
                {
                    _logger.LogWarning("Invalid username format detected: {Username}", username);
                    return null;
                }

                if (!InputSanitizer.IsValidEmail(email))
                {
                    _logger.LogWarning("Invalid email format detected: {Email}", email);
                    return null;
                }

                // SECURITY: Additional check for SQL injection patterns (defense in depth)
                if (InputSanitizer.ContainsSqlInjectionPatterns(username) || 
                    InputSanitizer.ContainsSqlInjectionPatterns(email))
                {
                    _logger.LogWarning("Potential SQL injection attempt detected. Username: {Username}, Email: {Email}", 
                        username, email);
                    return null;
                }

                // SECURITY: Check for XSS patterns
                if (InputSanitizer.ContainsXssPatterns(username) || 
                    InputSanitizer.ContainsXssPatterns(email))
                {
                    _logger.LogWarning("Potential XSS attempt detected. Username: {Username}, Email: {Email}", 
                        username, email);
                    return null;
                }

                // SECURITY: Sanitize inputs (XSS prevention)
                string sanitizedUsername = InputSanitizer.SanitizeForXss(username);
                string sanitizedEmail = InputSanitizer.SanitizeForXss(email);

                // Check if user already exists
                // SECURITY: This query is parameterized by Entity Framework Core
                var existingUser = await _context.Users
                    .Where(u => u.Username == sanitizedUsername || u.Email == sanitizedEmail)
                    .FirstOrDefaultAsync();

                if (existingUser != null)
                {
                    _logger.LogInformation("User already exists with username or email");
                    return null;
                }

                // Create new user
                var user = new User
                {
                    Username = sanitizedUsername,
                    Email = sanitizedEmail,
                    CreatedAt = DateTime.UtcNow
                };

                // SECURITY: Entity Framework Core uses parameterized queries
                // This INSERT statement is automatically parameterized, preventing SQL injection
                _context.Users.Add(user);
                await _context.SaveChangesAsync();

                _logger.LogInformation("User created successfully: {UserId}", user.UserID);
                return user;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error creating user. Username: {Username}, Email: {Email}", 
                    username, email);
                return null;
            }
        }

        /// <summary>
        /// Retrieves user by ID using parameterized query
        /// </summary>
        /// <param name="userId">User ID</param>
        /// <returns>User or null if not found</returns>
        public async Task<User?> GetUserByIdAsync(int userId)
        {
            try
            {
                // SECURITY: Parameterized query via Entity Framework Core
                return await _context.Users
                    .Where(u => u.UserID == userId)
                    .FirstOrDefaultAsync();
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error retrieving user by ID: {UserId}", userId);
                return null;
            }
        }

        /// <summary>
        /// Retrieves user by username using parameterized query
        /// </summary>
        /// <param name="username">Username (validated)</param>
        /// <returns>User or null if not found</returns>
        public async Task<User?> GetUserByUsernameAsync(string username)
        {
            try
            {
                // SECURITY: Validate input
                if (!InputSanitizer.IsValidUsername(username))
                {
                    _logger.LogWarning("Invalid username format in lookup: {Username}", username);
                    return null;
                }

                // SECURITY: Parameterized query via Entity Framework Core
                return await _context.Users
                    .Where(u => u.Username == username)
                    .FirstOrDefaultAsync();
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error retrieving user by username: {Username}", username);
                return null;
            }
        }

        /// <summary>
        /// Retrieves all users with pagination (secure)
        /// </summary>
        /// <param name="pageNumber">Page number (1-indexed)</param>
        /// <param name="pageSize">Number of records per page</param>
        /// <returns>List of users</returns>
        public async Task<List<User>> GetAllUsersAsync(int pageNumber = 1, int pageSize = 10)
        {
            try
            {
                // SECURITY: Validate pagination parameters to prevent resource exhaustion
                if (pageNumber < 1) pageNumber = 1;
                if (pageSize < 1 || pageSize > 100) pageSize = 10;

                // SECURITY: Parameterized query with pagination
                return await _context.Users
                    .OrderByDescending(u => u.CreatedAt)
                    .Skip((pageNumber - 1) * pageSize)
                    .Take(pageSize)
                    .ToListAsync();
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error retrieving users list");
                return new List<User>();
            }
        }

        /// <summary>
        /// Updates user email with validation
        /// </summary>
        /// <param name="userId">User ID</param>
        /// <param name="newEmail">New email address (validated)</param>
        /// <returns>True if successful, false otherwise</returns>
        public async Task<bool> UpdateUserEmailAsync(int userId, string newEmail)
        {
            try
            {
                // SECURITY: Validate email
                if (!InputSanitizer.IsValidEmail(newEmail))
                {
                    _logger.LogWarning("Invalid email format in update: {Email}", newEmail);
                    return false;
                }

                // SECURITY: Sanitize input
                string sanitizedEmail = InputSanitizer.SanitizeForXss(newEmail);

                // SECURITY: Parameterized query to find user
                var user = await _context.Users
                    .Where(u => u.UserID == userId)
                    .FirstOrDefaultAsync();

                if (user == null)
                {
                    _logger.LogWarning("User not found for update: {UserId}", userId);
                    return false;
                }

                // Check if email already exists for another user
                var existingEmail = await _context.Users
                    .Where(u => u.Email == sanitizedEmail && u.UserID != userId)
                    .FirstOrDefaultAsync();

                if (existingEmail != null)
                {
                    _logger.LogInformation("Email already in use by another user");
                    return false;
                }

                // SECURITY: Parameterized UPDATE query via Entity Framework Core
                user.Email = sanitizedEmail;
                await _context.SaveChangesAsync();

                _logger.LogInformation("User email updated successfully: {UserId}", userId);
                return true;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error updating user email. UserId: {UserId}", userId);
                return false;
            }
        }

        /// <summary>
        /// Deletes user by ID
        /// </summary>
        /// <param name="userId">User ID</param>
        /// <returns>True if successful, false otherwise</returns>
        public async Task<bool> DeleteUserAsync(int userId)
        {
            try
            {
                // SECURITY: Parameterized query
                var user = await _context.Users
                    .Where(u => u.UserID == userId)
                    .FirstOrDefaultAsync();

                if (user == null)
                {
                    _logger.LogWarning("User not found for deletion: {UserId}", userId);
                    return false;
                }

                // SECURITY: Parameterized DELETE query via Entity Framework Core
                _context.Users.Remove(user);
                await _context.SaveChangesAsync();

                _logger.LogInformation("User deleted successfully: {UserId}", userId);
                return true;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error deleting user. UserId: {UserId}", userId);
                return false;
            }
        }
    }
}
