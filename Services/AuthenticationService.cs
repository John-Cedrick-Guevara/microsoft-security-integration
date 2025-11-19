using Microsoft.EntityFrameworkCore;
using Secure.Data;
using Secure.Models;
using Secure.Utilities;

namespace Secure.Services
{
    /// <summary>
    /// Service for user authentication and account management
    /// Implements secure login, registration, and account lockout features
    /// </summary>
    public class AuthenticationService : IAuthenticationService
    {
        private readonly ApplicationDbContext _context;
        private readonly IPasswordHashingService _passwordHasher;
        private readonly ILogger<AuthenticationService> _logger;

        // SECURITY: Account lockout configuration
        private const int MaxFailedLoginAttempts = 5;
        private const int LockoutDurationMinutes = 15;

        public AuthenticationService(
            ApplicationDbContext context,
            IPasswordHashingService passwordHasher,
            ILogger<AuthenticationService> logger)
        {
            _context = context;
            _passwordHasher = passwordHasher;
            _logger = logger;
        }

        /// <summary>
        /// Authenticates a user with username and password
        /// SECURITY: Implements account lockout after failed attempts
        /// </summary>
        public async Task<AuthenticationResult> AuthenticateAsync(string username, string password)
        {
            try
            {
                // SECURITY: Validate inputs
                if (!InputSanitizer.IsValidUsername(username))
                {
                    _logger.LogWarning("Invalid username format in authentication attempt: {Username}", username);
                    return new AuthenticationResult
                    {
                        Success = false,
                        Message = "Invalid username or password"
                    };
                }

                // SECURITY: Retrieve user with parameterized query
                var user = await _context.Users
                    .Where(u => u.Username == username)
                    .FirstOrDefaultAsync();

                if (user == null)
                {
                    _logger.LogWarning("Authentication failed: User not found - {Username}", username);
                    // SECURITY: Don't reveal that user doesn't exist
                    return new AuthenticationResult
                    {
                        Success = false,
                        Message = "Invalid username or password"
                    };
                }

                // SECURITY: Check if account is locked
                if (user.LockoutEnd.HasValue && user.LockoutEnd.Value > DateTime.UtcNow)
                {
                    var remainingTime = (user.LockoutEnd.Value - DateTime.UtcNow).Minutes;
                    _logger.LogWarning("Login attempt for locked account: {Username}", username);
                    return new AuthenticationResult
                    {
                        Success = false,
                        Message = $"Account is locked. Try again in {remainingTime} minutes.",
                        IsLockedOut = true
                    };
                }

                // SECURITY: Check if account is active
                if (!user.IsActive)
                {
                    _logger.LogWarning("Login attempt for inactive account: {Username}", username);
                    return new AuthenticationResult
                    {
                        Success = false,
                        Message = "Account is disabled. Contact administrator."
                    };
                }

                // SECURITY: Verify password using BCrypt
                bool passwordValid = _passwordHasher.VerifyPassword(password, user.PasswordHash);

                if (!passwordValid)
                {
                    // SECURITY: Increment failed login attempts
                    user.FailedLoginAttempts++;

                    // SECURITY: Lock account after max attempts
                    if (user.FailedLoginAttempts >= MaxFailedLoginAttempts)
                    {
                        user.LockoutEnd = DateTime.UtcNow.AddMinutes(LockoutDurationMinutes);
                        _logger.LogWarning("Account locked due to failed login attempts: {Username}", username);
                        
                        await _context.SaveChangesAsync();
                        
                        return new AuthenticationResult
                        {
                            Success = false,
                            Message = $"Account locked for {LockoutDurationMinutes} minutes due to multiple failed login attempts.",
                            IsLockedOut = true
                        };
                    }

                    await _context.SaveChangesAsync();

                    int remainingAttempts = MaxFailedLoginAttempts - user.FailedLoginAttempts;
                    _logger.LogWarning("Failed login attempt for {Username}. Remaining attempts: {Remaining}", 
                        username, remainingAttempts);

                    return new AuthenticationResult
                    {
                        Success = false,
                        Message = "Invalid username or password",
                        RemainingAttempts = remainingAttempts
                    };
                }

                // SECURITY: Successful authentication - reset lockout counters
                user.FailedLoginAttempts = 0;
                user.LockoutEnd = null;
                user.LastLogin = DateTime.UtcNow;
                await _context.SaveChangesAsync();

                _logger.LogInformation("Successful authentication for user: {Username}", username);

                return new AuthenticationResult
                {
                    Success = true,
                    Message = "Authentication successful",
                    User = user
                };
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error during authentication for username: {Username}", username);
                return new AuthenticationResult
                {
                    Success = false,
                    Message = "An error occurred during authentication"
                };
            }
        }

        /// <summary>
        /// Registers a new user with secure password hashing
        /// </summary>
        public async Task<AuthenticationResult> RegisterAsync(string username, string email, string password, UserRole role = UserRole.User)
        {
            try
            {
                // SECURITY: Validate username
                if (!InputSanitizer.IsValidUsername(username))
                {
                    return new AuthenticationResult
                    {
                        Success = false,
                        Message = "Invalid username format"
                    };
                }

                // SECURITY: Validate email
                if (!InputSanitizer.IsValidEmail(email))
                {
                    return new AuthenticationResult
                    {
                        Success = false,
                        Message = "Invalid email format"
                    };
                }

                // SECURITY: Validate password strength
                var (isValid, message) = _passwordHasher.ValidatePasswordStrength(password);
                if (!isValid)
                {
                    return new AuthenticationResult
                    {
                        Success = false,
                        Message = message
                    };
                }

                // SECURITY: Check for XSS and SQL injection patterns
                if (InputSanitizer.ContainsXssPatterns(username) || 
                    InputSanitizer.ContainsSqlInjectionPatterns(username))
                {
                    _logger.LogWarning("Malicious input detected in registration: {Username}", username);
                    return new AuthenticationResult
                    {
                        Success = false,
                        Message = "Invalid input detected"
                    };
                }

                // Check if user already exists
                var existingUser = await _context.Users
                    .Where(u => u.Username == username || u.Email == email)
                    .FirstOrDefaultAsync();

                if (existingUser != null)
                {
                    _logger.LogWarning("Registration failed: Username or email already exists");
                    return new AuthenticationResult
                    {
                        Success = false,
                        Message = "Username or email already exists"
                    };
                }

                // SECURITY: Hash password using BCrypt
                string passwordHash = _passwordHasher.HashPassword(password);

                // Create new user
                var user = new User
                {
                    Username = InputSanitizer.SanitizeForXss(username),
                    Email = InputSanitizer.SanitizeForXss(email),
                    PasswordHash = passwordHash,
                    Role = role,
                    IsActive = true,
                    CreatedAt = DateTime.UtcNow
                };

                _context.Users.Add(user);
                await _context.SaveChangesAsync();

                _logger.LogInformation("New user registered: {Username} with role {Role}", username, role);

                return new AuthenticationResult
                {
                    Success = true,
                    Message = "Registration successful",
                    User = user
                };
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error during registration for username: {Username}", username);
                return new AuthenticationResult
                {
                    Success = false,
                    Message = "An error occurred during registration"
                };
            }
        }

        /// <summary>
        /// Changes user password with validation
        /// </summary>
        public async Task<bool> ChangePasswordAsync(int userId, string currentPassword, string newPassword)
        {
            try
            {
                var user = await _context.Users.FindAsync(userId);
                if (user == null)
                    return false;

                // Verify current password
                if (!_passwordHasher.VerifyPassword(currentPassword, user.PasswordHash))
                {
                    _logger.LogWarning("Failed password change attempt for user {UserId}: Invalid current password", userId);
                    return false;
                }

                // Validate new password strength
                var (isValid, message) = _passwordHasher.ValidatePasswordStrength(newPassword);
                if (!isValid)
                {
                    _logger.LogWarning("Password change failed for user {UserId}: {Message}", userId, message);
                    return false;
                }

                // Hash and save new password
                user.PasswordHash = _passwordHasher.HashPassword(newPassword);
                await _context.SaveChangesAsync();

                _logger.LogInformation("Password changed successfully for user {UserId}", userId);
                return true;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error changing password for user {UserId}", userId);
                return false;
            }
        }

        /// <summary>
        /// Unlocks a user account manually (admin function)
        /// </summary>
        public async Task<bool> UnlockAccountAsync(int userId)
        {
            try
            {
                var user = await _context.Users.FindAsync(userId);
                if (user == null)
                    return false;

                user.FailedLoginAttempts = 0;
                user.LockoutEnd = null;
                await _context.SaveChangesAsync();

                _logger.LogInformation("Account unlocked for user {UserId}", userId);
                return true;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error unlocking account for user {UserId}", userId);
                return false;
            }
        }

        /// <summary>
        /// Updates user role (admin function)
        /// </summary>
        public async Task<bool> UpdateUserRoleAsync(int userId, UserRole newRole)
        {
            try
            {
                var user = await _context.Users.FindAsync(userId);
                if (user == null)
                    return false;

                var oldRole = user.Role;
                user.Role = newRole;
                await _context.SaveChangesAsync();

                _logger.LogInformation("User {UserId} role changed from {OldRole} to {NewRole}", 
                    userId, oldRole, newRole);
                return true;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error updating role for user {UserId}", userId);
                return false;
            }
        }
    }

    /// <summary>
    /// Interface for authentication service
    /// </summary>
    public interface IAuthenticationService
    {
        Task<AuthenticationResult> AuthenticateAsync(string username, string password);
        Task<AuthenticationResult> RegisterAsync(string username, string email, string password, UserRole role = UserRole.User);
        Task<bool> ChangePasswordAsync(int userId, string currentPassword, string newPassword);
        Task<bool> UnlockAccountAsync(int userId);
        Task<bool> UpdateUserRoleAsync(int userId, UserRole newRole);
    }
}
