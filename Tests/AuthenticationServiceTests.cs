using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Moq;
using NUnit.Framework;
using Secure.Data;
using Secure.Models;
using Secure.Services;
using System;
using System.Threading.Tasks;

namespace Secure.Tests
{
    /// <summary>
    /// SECURITY TESTING: Authentication Service Tests
    /// Tests password hashing, login attempts, account lockout, and user registration
    /// </summary>
    [TestFixture]
    public class AuthenticationServiceTests
    {
        private ApplicationDbContext _context = null!;
        private IPasswordHashingService _passwordHashingService = null!;
        private IAuthenticationService _authService = null!;

        [SetUp]
        public void Setup()
        {
            var options = new DbContextOptionsBuilder<ApplicationDbContext>()
                .UseInMemoryDatabase(databaseName: Guid.NewGuid().ToString())
                .Options;

            _context = new ApplicationDbContext(options);
            _passwordHashingService = new PasswordHashingService();
            var mockLogger = new Mock<ILogger<AuthenticationService>>();
            _authService = new AuthenticationService(_context, _passwordHashingService, mockLogger.Object);
            _context.Database.EnsureCreated();
        }

        [TearDown]
        public void TearDown()
        {
            _context?.Dispose();
        }

        #region Login Tests

        [Test]
        public async Task Login_ValidCredentials_ReturnsSuccess()
        {
            var username = "testuser";
            var password = "Test@123";
            await _authService.RegisterAsync(username, "test@example.com", password);

            var result = await _authService.AuthenticateAsync(username, password);

            Assert.That(result.Success, Is.True);
            Assert.That(result.Message, Is.EqualTo("Authentication successful"));
            Assert.That(result.User, Is.Not.Null);
            Assert.That(result.User!.Username, Is.EqualTo(username));
        }

        [Test]
        public async Task Login_InvalidPassword_ReturnsFailure()
        {
            var username = "testuser";
            await _authService.RegisterAsync(username, "test@example.com", "Test@123");

            var result = await _authService.AuthenticateAsync(username, "Wrong@123");

            Assert.That(result.Success, Is.False);
            Assert.That(result.Message, Is.EqualTo("Invalid username or password"));
        }

        [Test]
        public async Task Login_InactiveAccount_ReturnsFailure()
        {
            var username = "testuser";
            await _authService.RegisterAsync(username, "test@example.com", "Test@123");
            
            var user = await _context.Users.FirstOrDefaultAsync(u => u.Username == username);
            user!.IsActive = false;
            await _context.SaveChangesAsync();

            var result = await _authService.AuthenticateAsync(username, "Test@123");

            Assert.That(result.Success, Is.False);
            Assert.That(result.Message, Is.EqualTo("Account is disabled. Contact administrator."));
        }

        #endregion

        #region Account Lockout Tests

        [Test]
        public async Task Login_FiveFailedAttempts_LocksAccount()
        {
            var username = "testuser";
            await _authService.RegisterAsync(username, "test@example.com", "Test@123");

            for (int i = 0; i < 5; i++)
            {
                await _authService.AuthenticateAsync(username, "Wrong@123");
            }

            var lockedResult = await _authService.AuthenticateAsync(username, "Test@123");

            Assert.That(lockedResult.Success, Is.False);
            Assert.That(lockedResult.Message, Does.Contain("Account is locked"));
            
            var user = await _context.Users.FirstOrDefaultAsync(u => u.Username == username);
            Assert.That(user!.FailedLoginAttempts, Is.EqualTo(5));
            Assert.That(user.LockoutEnd, Is.Not.Null);
        }

        [Test]
        public async Task UnlockAccount_LockedAccount_RemovesLockout()
        {
            var username = "testuser";
            await _authService.RegisterAsync(username, "test@example.com", "Test@123");
            
            var user = await _context.Users.FirstOrDefaultAsync(u => u.Username == username);
            user!.FailedLoginAttempts = 5;
            user.LockoutEnd = DateTime.UtcNow.AddHours(1);
            await _context.SaveChangesAsync();

            var result = await _authService.UnlockAccountAsync(user.UserID);

            Assert.That(result, Is.True);
            Assert.That(user.FailedLoginAttempts, Is.EqualTo(0));
            Assert.That(user.LockoutEnd, Is.Null);
        }

        #endregion

        #region Registration Tests

        [Test]
        public async Task Register_ValidData_CreatesUser()
        {
            var result = await _authService.RegisterAsync("newuser", "new@example.com", "Secure@123");

            Assert.That(result.Success, Is.True);
            var user = await _context.Users.FirstOrDefaultAsync(u => u.Username == "newuser");
            Assert.That(user, Is.Not.Null);
            Assert.That(user!.Role, Is.EqualTo(UserRole.User));
        }

        [Test]
        public async Task Register_WeakPassword_ReturnsFailure()
        {
            var result = await _authService.RegisterAsync("testuser", "test@example.com", "weak");

            Assert.That(result.Success, Is.False);
            Assert.That(result.Message, Does.Contain("Password"));
        }

        [Test]
        public async Task Register_DuplicateUsername_ReturnsFailure()
        {
            await _authService.RegisterAsync("duplicate", "first@example.com", "Test@123");
            var result = await _authService.RegisterAsync("duplicate", "second@example.com", "Test@456");

            Assert.That(result.Success, Is.False);
            Assert.That(result.Message, Does.Contain("already exists"));
        }

        #endregion

        #region Password Security Tests

        [Test]
        public void PasswordHashing_SamePassword_GeneratesDifferentHashes()
        {
            var password = "Test@123";
            var hash1 = _passwordHashingService.HashPassword(password);
            var hash2 = _passwordHashingService.HashPassword(password);

            Assert.That(hash1, Is.Not.EqualTo(hash2));
        }

        [Test]
        public void PasswordVerification_CorrectPassword_ReturnsTrue()
        {
            var password = "Test@123";
            var hash = _passwordHashingService.HashPassword(password);

            var result = _passwordHashingService.VerifyPassword(password, hash);

            Assert.That(result, Is.True);
        }

        [Test]
        public async Task ChangePassword_ValidOldPassword_UpdatesPassword()
        {
            await _authService.RegisterAsync("testuser", "test@example.com", "OldPass@123");
            var user = await _context.Users.FirstOrDefaultAsync(u => u.Username == "testuser");

            var result = await _authService.ChangePasswordAsync(user!.UserID, "OldPass@123", "NewPass@456");

            Assert.That(result, Is.True);
            var loginResult = await _authService.AuthenticateAsync("testuser", "NewPass@456");
            Assert.That(loginResult.Success, Is.True);
        }

        #endregion

        #region Role Management Tests

        [Test]
        public async Task UpdateRole_ValidUser_ChangesRole()
        {
            await _authService.RegisterAsync("testuser", "test@example.com", "Test@123");
            var user = await _context.Users.FirstOrDefaultAsync(u => u.Username == "testuser");

            var result = await _authService.UpdateUserRoleAsync(user!.UserID, UserRole.Admin);

            Assert.That(result, Is.True);
            Assert.That(user.Role, Is.EqualTo(UserRole.Admin));
        }

        #endregion
    }
}
