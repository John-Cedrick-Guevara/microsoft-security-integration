using BCrypt.Net;

namespace Secure.Services
{
    /// <summary>
    /// Service for secure password hashing using BCrypt
    /// BCrypt is a strong, adaptive hashing function designed for passwords
    /// </summary>
    public class PasswordHashingService : IPasswordHashingService
    {
        // SECURITY: Work factor for BCrypt (higher = more secure but slower)
        // 12 is a good balance between security and performance
        private const int WorkFactor = 12;

        /// <summary>
        /// Hashes a password using BCrypt with salt
        /// SECURITY: BCrypt automatically generates and includes a salt
        /// </summary>
        /// <param name="password">Plain text password</param>
        /// <returns>Hashed password with embedded salt</returns>
        public string HashPassword(string password)
        {
            if (string.IsNullOrWhiteSpace(password))
                throw new ArgumentException("Password cannot be null or empty", nameof(password));

            // SECURITY: BCrypt.HashPassword automatically:
            // 1. Generates a cryptographically secure random salt
            // 2. Applies the salt to the password
            // 3. Performs multiple rounds of hashing (work factor)
            // 4. Returns hash with embedded salt (no separate storage needed)
            return BCrypt.Net.BCrypt.HashPassword(password, WorkFactor);
        }

        /// <summary>
        /// Verifies a password against a BCrypt hash
        /// SECURITY: Uses constant-time comparison to prevent timing attacks
        /// </summary>
        /// <param name="password">Plain text password to verify</param>
        /// <param name="hashedPassword">BCrypt hash to compare against</param>
        /// <returns>True if password matches, false otherwise</returns>
        public bool VerifyPassword(string password, string hashedPassword)
        {
            if (string.IsNullOrWhiteSpace(password))
                return false;

            if (string.IsNullOrWhiteSpace(hashedPassword))
                return false;

            try
            {
                // SECURITY: BCrypt.Verify performs constant-time comparison
                // This prevents timing attacks where an attacker could determine
                // if a password is partially correct based on response time
                return BCrypt.Net.BCrypt.Verify(password, hashedPassword);
            }
            catch (Exception)
            {
                // Invalid hash format or other error
                return false;
            }
        }

        /// <summary>
        /// Checks if a password hash needs to be rehashed
        /// Use this to upgrade hashes when work factor increases
        /// </summary>
        /// <param name="hashedPassword">Existing hash</param>
        /// <returns>True if rehashing recommended</returns>
        public bool NeedsRehash(string hashedPassword)
        {
            try
            {
                // Check if the hash was created with a different work factor
                return !BCrypt.Net.BCrypt.PasswordNeedsRehash(hashedPassword, WorkFactor);
            }
            catch
            {
                return true;
            }
        }

        /// <summary>
        /// Validates password strength
        /// SECURITY: Enforces strong password requirements
        /// </summary>
        /// <param name="password">Password to validate</param>
        /// <returns>Validation result and message</returns>
        public (bool isValid, string message) ValidatePasswordStrength(string password)
        {
            if (string.IsNullOrWhiteSpace(password))
                return (false, "Password cannot be empty");

            if (password.Length < 8)
                return (false, "Password must be at least 8 characters long");

            if (password.Length > 100)
                return (false, "Password must not exceed 100 characters");

            // Check for uppercase letter
            if (!password.Any(char.IsUpper))
                return (false, "Password must contain at least one uppercase letter");

            // Check for lowercase letter
            if (!password.Any(char.IsLower))
                return (false, "Password must contain at least one lowercase letter");

            // Check for digit
            if (!password.Any(char.IsDigit))
                return (false, "Password must contain at least one number");

            // Check for special character
            if (!password.Any(ch => !char.IsLetterOrDigit(ch)))
                return (false, "Password must contain at least one special character");

            // Check for common weak passwords
            var weakPasswords = new[]
            {
                "Password123!", "Admin123!", "Welcome123!", "Qwerty123!",
                "Password1!", "12345678!", "Abcd1234!"
            };

            if (weakPasswords.Any(weak => password.Equals(weak, StringComparison.OrdinalIgnoreCase)))
                return (false, "Password is too common. Please choose a stronger password");

            return (true, "Password meets all requirements");
        }
    }

    /// <summary>
    /// Interface for password hashing service
    /// </summary>
    public interface IPasswordHashingService
    {
        string HashPassword(string password);
        bool VerifyPassword(string password, string hashedPassword);
        bool NeedsRehash(string hashedPassword);
        (bool isValid, string message) ValidatePasswordStrength(string password);
    }
}
