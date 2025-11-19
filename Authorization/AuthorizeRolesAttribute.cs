using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;
using Secure.Models;
using System.Security.Claims;

namespace Secure.Authorization
{
    /// <summary>
    /// Authorization attribute to restrict access based on user roles
    /// SECURITY: Implements Role-Based Access Control (RBAC)
    /// </summary>
    [AttributeUsage(AttributeTargets.Class | AttributeTargets.Method, AllowMultiple = true)]
    public class AuthorizeRolesAttribute : Attribute, IAuthorizationFilter
    {
        private readonly UserRole[] _allowedRoles;

        /// <summary>
        /// Initializes role-based authorization
        /// </summary>
        /// <param name="allowedRoles">Roles that can access this resource</param>
        public AuthorizeRolesAttribute(params UserRole[] allowedRoles)
        {
            _allowedRoles = allowedRoles ?? Array.Empty<UserRole>();
        }

        /// <summary>
        /// SECURITY: Validates user has required role before allowing access
        /// </summary>
        public void OnAuthorization(AuthorizationFilterContext context)
        {
            // Check if user is authenticated
            if (!context.HttpContext.User.Identity?.IsAuthenticated ?? true)
            {
                // SECURITY: Redirect unauthenticated users to login
                context.Result = new RedirectToActionResult("Login", "Auth", null);
                return;
            }

            // Get user role from claims
            var roleClaim = context.HttpContext.User.FindFirst(ClaimTypes.Role)?.Value;
            
            if (string.IsNullOrEmpty(roleClaim))
            {
                // SECURITY: No role claim found - deny access
                context.Result = new ForbidResult();
                return;
            }

            // Parse role
            if (!Enum.TryParse<UserRole>(roleClaim, out var userRole))
            {
                // SECURITY: Invalid role - deny access
                context.Result = new ForbidResult();
                return;
            }

            // SECURITY: Check if user's role is in allowed roles
            if (!_allowedRoles.Contains(userRole))
            {
                // SECURITY: User doesn't have required role - show access denied
                context.Result = new RedirectToActionResult("AccessDenied", "Auth", null);
                return;
            }

            // User has required role - allow access
        }
    }

    /// <summary>
    /// Convenience attributes for common role requirements
    /// </summary>
    public class AdminOnlyAttribute : AuthorizeRolesAttribute
    {
        public AdminOnlyAttribute() : base(UserRole.Admin) { }
    }

    public class ModeratorOrAdminAttribute : AuthorizeRolesAttribute
    {
        public ModeratorOrAdminAttribute() : base(UserRole.Admin, UserRole.Moderator) { }
    }

    /// <summary>
    /// Custom authorization filter to check if user is authenticated
    /// </summary>
    public class RequireAuthenticationAttribute : Attribute, IAuthorizationFilter
    {
        public void OnAuthorization(AuthorizationFilterContext context)
        {
            if (!context.HttpContext.User.Identity?.IsAuthenticated ?? true)
            {
                context.Result = new RedirectToActionResult("Login", "Auth", null);
            }
        }
    }
}
