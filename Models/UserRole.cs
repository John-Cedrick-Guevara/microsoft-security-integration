namespace Secure.Models
{
    /// <summary>
    /// User roles for role-based access control (RBAC)
    /// </summary>
    public enum UserRole
    {
        /// <summary>
        /// Regular user with basic access
        /// </summary>
        User = 0,

        /// <summary>
        /// Administrator with full access to all features
        /// </summary>
        Admin = 1,

        /// <summary>
        /// Moderator with elevated privileges
        /// </summary>
        Moderator = 2
    }
}
