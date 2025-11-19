using System.ComponentModel.DataAnnotations;

namespace Secure.Models
{
    /// <summary>
    /// User entity for database storage with authentication and authorization
    /// </summary>
    public class User
    {
        [Key]
        public int UserID { get; set; }

        [Required]
        [StringLength(50, MinimumLength = 3)]
        [RegularExpression(@"^[a-zA-Z0-9_]+$", ErrorMessage = "Username can only contain letters, numbers, and underscores")]
        public string Username { get; set; } = string.Empty;

        [Required]
        [EmailAddress]
        [StringLength(100)]
        public string Email { get; set; } = string.Empty;

        /// <summary>
        /// SECURITY: Hashed password using BCrypt
        /// Never store plain text passwords!
        /// </summary>
        [Required]
        public string PasswordHash { get; set; } = string.Empty;

        /// <summary>
        /// User role for authorization (User, Admin, Moderator)
        /// </summary>
        [Required]
        public UserRole Role { get; set; } = UserRole.User;

        /// <summary>
        /// Account active status
        /// </summary>
        public bool IsActive { get; set; } = true;

        /// <summary>
        /// Number of failed login attempts (for account lockout)
        /// </summary>
        public int FailedLoginAttempts { get; set; } = 0;

        /// <summary>
        /// Account lockout timestamp
        /// </summary>
        public DateTime? LockoutEnd { get; set; }

        /// <summary>
        /// Last successful login timestamp
        /// </summary>
        public DateTime? LastLogin { get; set; }

        public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    }
}
