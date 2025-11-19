using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Abstractions;
using Microsoft.AspNetCore.Mvc.Filters;
using Microsoft.AspNetCore.Routing;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Moq;
using NUnit.Framework;
using Secure.Authorization;
using Secure.Data;
using Secure.Models;
using Secure.Services;
using System;
using System.Collections.Generic;
using System.Security.Claims;
using System.Threading.Tasks;

namespace Secure.Tests
{
    /// <summary>
    /// SECURITY TESTING: Authorization Tests
    /// Tests role-based access control and unauthorized access prevention
    /// </summary>
    [TestFixture]
    public class AuthorizationTests
    {
        private ApplicationDbContext _context = null!;
        private Mock<HttpContext> _mockHttpContext = null!;
        private AuthorizationFilterContext _filterContext = null!;

        [SetUp]
        public void Setup()
        {
            var options = new DbContextOptionsBuilder<ApplicationDbContext>()
                .UseInMemoryDatabase(databaseName: Guid.NewGuid().ToString())
                .Options;

            _context = new ApplicationDbContext(options);
            _context.Database.EnsureCreated();

            _mockHttpContext = new Mock<HttpContext>();
            var actionContext = new ActionContext(
                _mockHttpContext.Object,
                new RouteData(),
                new ActionDescriptor()
            );
            _filterContext = new AuthorizationFilterContext(
                actionContext,
                new List<IFilterMetadata>()
            );
        }

        [TearDown]
        public void TearDown()
        {
            _context?.Dispose();
        }

        #region Helper Methods

        private void SetupUserClaims(string username, string role, bool isAuthenticated = true)
        {
            var claims = new List<Claim>
            {
                new Claim(ClaimTypes.NameIdentifier, "1"),
                new Claim(ClaimTypes.Name, username),
                new Claim(ClaimTypes.Email, $"{username}@example.com"),
                new Claim(ClaimTypes.Role, role)
            };

            var identity = new ClaimsIdentity(claims, isAuthenticated ? "TestAuth" : null);
            var principal = new ClaimsPrincipal(identity);
            _mockHttpContext.Setup(x => x.User).Returns(principal);
        }

        #endregion

        #region AdminOnly Attribute Tests

        [Test]
        public void AdminOnly_UnauthenticatedUser_RedirectsToLogin()
        {
            var attribute = new AdminOnlyAttribute();
            SetupUserClaims("guest", "User", isAuthenticated: false);

            attribute.OnAuthorization(_filterContext);

            Assert.That(_filterContext.Result, Is.InstanceOf<RedirectToActionResult>());
            var redirect = _filterContext.Result as RedirectToActionResult;
            Assert.That(redirect!.ControllerName, Is.EqualTo("Auth"));
            Assert.That(redirect.ActionName, Is.EqualTo("Login"));
        }

        [Test]
        public void AdminOnly_RegularUser_RedirectsToAccessDenied()
        {
            var attribute = new AdminOnlyAttribute();
            SetupUserClaims("regularuser", "User", isAuthenticated: true);

            attribute.OnAuthorization(_filterContext);

            Assert.That(_filterContext.Result, Is.InstanceOf<RedirectToActionResult>());
            var redirect = _filterContext.Result as RedirectToActionResult;
            Assert.That(redirect!.ActionName, Is.EqualTo("AccessDenied"));
        }

        [Test]
        public void AdminOnly_AdminUser_AllowsAccess()
        {
            var attribute = new AdminOnlyAttribute();
            SetupUserClaims("adminuser", "Admin", isAuthenticated: true);

            attribute.OnAuthorization(_filterContext);

            Assert.That(_filterContext.Result, Is.Null);
        }

        #endregion

        #region ModeratorOrAdmin Attribute Tests

        [Test]
        public void ModeratorOrAdmin_RegularUser_RedirectsToAccessDenied()
        {
            var attribute = new ModeratorOrAdminAttribute();
            SetupUserClaims("regularuser", "User", isAuthenticated: true);

            attribute.OnAuthorization(_filterContext);

            Assert.That(_filterContext.Result, Is.InstanceOf<RedirectToActionResult>());
        }

        [Test]
        public void ModeratorOrAdmin_ModeratorUser_AllowsAccess()
        {
            var attribute = new ModeratorOrAdminAttribute();
            SetupUserClaims("moderator", "Moderator", isAuthenticated: true);

            attribute.OnAuthorization(_filterContext);

            Assert.That(_filterContext.Result, Is.Null);
        }

        [Test]
        public void ModeratorOrAdmin_AdminUser_AllowsAccess()
        {
            var attribute = new ModeratorOrAdminAttribute();
            SetupUserClaims("admin", "Admin", isAuthenticated: true);

            attribute.OnAuthorization(_filterContext);

            Assert.That(_filterContext.Result, Is.Null);
        }

        #endregion

        #region RequireAuthentication Attribute Tests

        [Test]
        public void RequireAuthentication_UnauthenticatedUser_RedirectsToLogin()
        {
            var attribute = new RequireAuthenticationAttribute();
            SetupUserClaims("guest", "User", isAuthenticated: false);

            attribute.OnAuthorization(_filterContext);

            Assert.That(_filterContext.Result, Is.InstanceOf<RedirectToActionResult>());
        }

        [Test]
        public void RequireAuthentication_AuthenticatedUser_AllowsAccess()
        {
            var attribute = new RequireAuthenticationAttribute();
            SetupUserClaims("user", "User", isAuthenticated: true);

            attribute.OnAuthorization(_filterContext);

            Assert.That(_filterContext.Result, Is.Null);
        }

        #endregion

        #region Custom Roles Attribute Tests

        [Test]
        public void AuthorizeRoles_MultipleRoles_AllowsMatchingRole()
        {
            var attribute = new AuthorizeRolesAttribute(UserRole.Admin, UserRole.Moderator);
            SetupUserClaims("moderator", "Moderator", isAuthenticated: true);

            attribute.OnAuthorization(_filterContext);

            Assert.That(_filterContext.Result, Is.Null);
        }

        [Test]
        public void AuthorizeRoles_MultipleRoles_BlocksNonMatchingRole()
        {
            var attribute = new AuthorizeRolesAttribute(UserRole.Admin, UserRole.Moderator);
            SetupUserClaims("regularuser", "User", isAuthenticated: true);

            attribute.OnAuthorization(_filterContext);

            Assert.That(_filterContext.Result, Is.InstanceOf<RedirectToActionResult>());
        }

        #endregion

        #region Security Edge Cases

        [Test]
        public void Authorization_MissingRoleClaim_RedirectsToAccessDenied()
        {
            var attribute = new AdminOnlyAttribute();
            
            var claims = new List<Claim>
            {
                new Claim(ClaimTypes.NameIdentifier, "1"),
                new Claim(ClaimTypes.Name, "testuser")
            };
            var identity = new ClaimsIdentity(claims, "TestAuth");
            var principal = new ClaimsPrincipal(identity);
            _mockHttpContext.Setup(x => x.User).Returns(principal);

            attribute.OnAuthorization(_filterContext);

            Assert.That(_filterContext.Result, Is.Not.Null);
        }

        [Test]
        public void Authorization_InvalidRoleValue_RedirectsToAccessDenied()
        {
            var attribute = new AdminOnlyAttribute();
            SetupUserClaims("user", "InvalidRole", isAuthenticated: true);

            attribute.OnAuthorization(_filterContext);

            Assert.That(_filterContext.Result, Is.Not.Null);
        }

        #endregion
    }
}
