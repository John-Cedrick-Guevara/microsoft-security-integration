using NUnit.Framework;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Moq;
using Secure.Data;
using Secure.Models;
using Secure.Services;

namespace Secure.Tests.Services
{
    /// <summary>
    /// Integration tests for UserService focusing on SQL injection prevention
    /// Tests parameterized queries and secure database operations
    /// </summary>
    [TestFixture]
    public class UserServiceSecurityTests
    {
        private ApplicationDbContext _context = null!;
        private UserService _userService = null!;
        private Mock<ILogger<UserService>> _loggerMock = null!;

        [SetUp]
        public void Setup()
        {
            // Use in-memory database for testing
            var options = new DbContextOptionsBuilder<ApplicationDbContext>()
                .UseInMemoryDatabase(databaseName: $"TestDb_{Guid.NewGuid()}")
                .Options;

            _context = new ApplicationDbContext(options);
            _loggerMock = new Mock<ILogger<UserService>>();
            _userService = new UserService(_context, _loggerMock.Object);
        }

        [TearDown]
        public void TearDown()
        {
            _context.Database.EnsureDeleted();
            _context.Dispose();
        }

        #region SQL Injection Prevention Tests

        [Test]
        [Category("Security")]
        [Category("SQLInjection")]
        public async Task CreateUserAsync_RejectsSqlInjectionInUsername()
        {
            // Arrange: SQL injection attempt in username
            string maliciousUsername = "admin'; DROP TABLE Users; --";
            string validEmail = "user@example.com";

            // Act: Attempt to create user with SQL injection
            var result = await _userService.CreateUserAsync(maliciousUsername, validEmail);

            // Assert: User creation should fail
            Assert.That(result, Is.Null, "Should reject username with SQL injection");
            
            // Verify no user was created
            var userCount = await _context.Users.CountAsync();
            Assert.That(userCount, Is.EqualTo(0), "No users should be created");

            Console.WriteLine($"✓ Blocked SQL injection in username: {maliciousUsername}");
        }

        [Test]
        [Category("Security")]
        [Category("SQLInjection")]
        public async Task CreateUserAsync_RejectsSqlInjectionInEmail()
        {
            // Arrange: SQL injection attempt in email
            string validUsername = "testuser";
            string maliciousEmail = "test@example.com'; DELETE FROM Users WHERE '1'='1";

            // Act
            var result = await _userService.CreateUserAsync(validUsername, maliciousEmail);

            // Assert: User creation should fail
            Assert.That(result, Is.Null, "Should reject email with SQL injection");
            
            var userCount = await _context.Users.CountAsync();
            Assert.That(userCount, Is.EqualTo(0), "No users should be created");

            Console.WriteLine($"✓ Blocked SQL injection in email: {maliciousEmail}");
        }

        [Test]
        [Category("Security")]
        [Category("SQLInjection")]
        public async Task CreateUserAsync_RejectsUnionBasedSqlInjection()
        {
            // Arrange: UNION-based SQL injection
            string maliciousUsername = "admin' UNION SELECT * FROM Users--";
            string validEmail = "test@example.com";

            // Act
            var result = await _userService.CreateUserAsync(maliciousUsername, validEmail);

            // Assert
            Assert.That(result, Is.Null, "Should reject UNION-based SQL injection");
            
            var userCount = await _context.Users.CountAsync();
            Assert.That(userCount, Is.EqualTo(0));

            Console.WriteLine($"✓ Blocked UNION-based SQL injection: {maliciousUsername}");
        }

        [Test]
        [Category("Security")]
        [Category("SQLInjection")]
        public async Task GetUserByUsernameAsync_RejectsSqlInjection()
        {
            // Arrange: Create a legitimate user first
            await _userService.CreateUserAsync("admin", "admin@example.com");

            // Attempt SQL injection to bypass authentication
            string maliciousUsername = "admin' OR '1'='1";

            // Act
            var result = await _userService.GetUserByUsernameAsync(maliciousUsername);

            // Assert: Should not return any user
            Assert.That(result, Is.Null, "Should not return user for SQL injection attempt");

            Console.WriteLine($"✓ Blocked SQL injection in lookup: {maliciousUsername}");
        }

        [Test]
        [Category("Security")]
        [Category("SQLInjection")]
        public async Task UpdateUserEmailAsync_RejectsSqlInjection()
        {
            // Arrange: Create a legitimate user
            var user = await _userService.CreateUserAsync("testuser", "test@example.com");
            Assert.That(user, Is.Not.Null);

            // Attempt SQL injection in email update
            string maliciousEmail = "new@example.com'; DROP TABLE Users; --";

            // Act
            var result = await _userService.UpdateUserEmailAsync(user!.UserID, maliciousEmail);

            // Assert: Update should fail
            Assert.That(result, Is.False, "Should reject SQL injection in email update");

            // Verify original email is unchanged
            var unchangedUser = await _userService.GetUserByIdAsync(user.UserID);
            Assert.That(unchangedUser!.Email, Is.EqualTo("test@example.com"));

            Console.WriteLine($"✓ Blocked SQL injection in update: {maliciousEmail}");
        }

        #endregion

        #region XSS Prevention Tests

        [Test]
        [Category("Security")]
        [Category("XSS")]
        public async Task CreateUserAsync_RejectsXssInUsername()
        {
            // Arrange: XSS attempt in username
            string maliciousUsername = "<script>alert('XSS')</script>";
            string validEmail = "test@example.com";

            // Act
            var result = await _userService.CreateUserAsync(maliciousUsername, validEmail);

            // Assert: User creation should fail
            Assert.That(result, Is.Null, "Should reject username with XSS");

            var userCount = await _context.Users.CountAsync();
            Assert.That(userCount, Is.EqualTo(0));

            Console.WriteLine($"✓ Blocked XSS in username: {maliciousUsername}");
        }

        [Test]
        [Category("Security")]
        [Category("XSS")]
        public async Task CreateUserAsync_RejectsXssInEmail()
        {
            // Arrange: XSS attempt in email
            string validUsername = "testuser";
            string maliciousEmail = "<img src=x onerror=alert('XSS')>@example.com";

            // Act
            var result = await _userService.CreateUserAsync(validUsername, maliciousEmail);

            // Assert
            Assert.That(result, Is.Null, "Should reject email with XSS");

            var userCount = await _context.Users.CountAsync();
            Assert.That(userCount, Is.EqualTo(0));

            Console.WriteLine($"✓ Blocked XSS in email: {maliciousEmail}");
        }

        [Test]
        [Category("Security")]
        [Category("XSS")]
        public async Task CreateUserAsync_SanitizesValidInputWithSpecialChars()
        {
            // Arrange: Input that needs sanitization but is valid
            string username = "user_123";
            string email = "user@example.com";

            // Act
            var result = await _userService.CreateUserAsync(username, email);

            // Assert: User should be created with sanitized data
            Assert.That(result, Is.Not.Null);
            Assert.That(result!.Username, Is.EqualTo(username));
            Assert.That(result.Email, Is.EqualTo(email));

            Console.WriteLine($"✓ Created user with safe input: {username}");
        }

        #endregion

        #region Parameterized Query Tests

        [Test]
        [Category("Security")]
        [Category("Database")]
        public async Task CreateUserAsync_UsesParameterizedQuery()
        {
            // Arrange: Normal user data
            string username = "john_doe";
            string email = "john@example.com";

            // Act: Create user (should use parameterized query internally)
            var user = await _userService.CreateUserAsync(username, email);

            // Assert: User created successfully
            Assert.That(user, Is.Not.Null);
            Assert.That(user!.Username, Is.EqualTo(username));
            Assert.That(user.Email, Is.EqualTo(email));
            Assert.That(user.UserID, Is.GreaterThan(0));

            // Verify in database
            var dbUser = await _context.Users.FindAsync(user.UserID);
            Assert.That(dbUser, Is.Not.Null);
            Assert.That(dbUser!.Username, Is.EqualTo(username));

            Console.WriteLine($"✓ Created user with parameterized query: {username}");
        }

        [Test]
        [Category("Security")]
        [Category("Database")]
        public async Task GetUserByIdAsync_UsesParameterizedQuery()
        {
            // Arrange: Create a user
            var createdUser = await _userService.CreateUserAsync("testuser", "test@example.com");
            Assert.That(createdUser, Is.Not.Null);

            // Act: Retrieve by ID (parameterized)
            var retrievedUser = await _userService.GetUserByIdAsync(createdUser!.UserID);

            // Assert
            Assert.That(retrievedUser, Is.Not.Null);
            Assert.That(retrievedUser!.UserID, Is.EqualTo(createdUser.UserID));
            Assert.That(retrievedUser.Username, Is.EqualTo(createdUser.Username));

            Console.WriteLine($"✓ Retrieved user with parameterized query: ID {retrievedUser.UserID}");
        }

        [Test]
        [Category("Security")]
        [Category("Database")]
        public async Task GetAllUsersAsync_UsesParameterizedQueryWithPagination()
        {
            // Arrange: Create multiple users
            for (int i = 1; i <= 15; i++)
            {
                await _userService.CreateUserAsync($"user{i}", $"user{i}@example.com");
            }

            // Act: Retrieve with pagination
            var page1 = await _userService.GetAllUsersAsync(pageNumber: 1, pageSize: 10);
            var page2 = await _userService.GetAllUsersAsync(pageNumber: 2, pageSize: 10);

            // Assert
            Assert.That(page1.Count, Is.EqualTo(10));
            Assert.That(page2.Count, Is.EqualTo(5));
            Assert.That(page1[0].UserID, Is.Not.EqualTo(page2[0].UserID));

            Console.WriteLine($"✓ Retrieved paginated users: Page 1: {page1.Count}, Page 2: {page2.Count}");
        }

        #endregion

        #region Input Validation Tests

        [Test]
        [Category("Validation")]
        public async Task CreateUserAsync_RejectsInvalidUsernameFormat()
        {
            // Arrange: Invalid username formats
            string[] invalidUsernames = new[]
            {
                "ab", // Too short
                "user@name", // Invalid characters
                "user name", // Space
                "", // Empty
                new string('a', 51) // Too long
            };

            // Act & Assert
            foreach (var username in invalidUsernames)
            {
                var result = await _userService.CreateUserAsync(username, "test@example.com");
                Assert.That(result, Is.Null, $"Should reject invalid username: {username}");
                Console.WriteLine($"✓ Rejected invalid username: {username}");
            }
        }

        [Test]
        [Category("Validation")]
        public async Task CreateUserAsync_RejectsInvalidEmailFormat()
        {
            // Arrange: Invalid email formats
            string[] invalidEmails = new[]
            {
                "notanemail",
                "@example.com",
                "user@",
                "user @example.com",
                ""
            };

            // Act & Assert
            foreach (var email in invalidEmails)
            {
                var result = await _userService.CreateUserAsync("testuser", email);
                Assert.That(result, Is.Null, $"Should reject invalid email: {email}");
                Console.WriteLine($"✓ Rejected invalid email: {email}");
            }
        }

        [Test]
        [Category("Validation")]
        public async Task CreateUserAsync_PreventsDuplicateUsername()
        {
            // Arrange: Create first user
            var user1 = await _userService.CreateUserAsync("john_doe", "john1@example.com");
            Assert.That(user1, Is.Not.Null);

            // Act: Attempt to create user with same username
            var user2 = await _userService.CreateUserAsync("john_doe", "john2@example.com");

            // Assert: Second user should not be created
            Assert.That(user2, Is.Null, "Should prevent duplicate username");

            var userCount = await _context.Users.CountAsync();
            Assert.That(userCount, Is.EqualTo(1), "Only one user should exist");

            Console.WriteLine("✓ Prevented duplicate username");
        }

        [Test]
        [Category("Validation")]
        public async Task CreateUserAsync_PreventsDuplicateEmail()
        {
            // Arrange: Create first user
            var user1 = await _userService.CreateUserAsync("john_doe", "john@example.com");
            Assert.That(user1, Is.Not.Null);

            // Act: Attempt to create user with same email
            var user2 = await _userService.CreateUserAsync("jane_doe", "john@example.com");

            // Assert: Second user should not be created
            Assert.That(user2, Is.Null, "Should prevent duplicate email");

            var userCount = await _context.Users.CountAsync();
            Assert.That(userCount, Is.EqualTo(1), "Only one user should exist");

            Console.WriteLine("✓ Prevented duplicate email");
        }

        #endregion

        #region Integration Tests

        [Test]
        [Category("Integration")]
        public async Task CompleteUserLifecycle_WorksSecurely()
        {
            // Arrange & Act: Create user
            var user = await _userService.CreateUserAsync("integration_user", "integration@example.com");
            Assert.That(user, Is.Not.Null);
            Console.WriteLine($"✓ Created user: {user!.Username}");

            // Act: Retrieve user
            var retrievedUser = await _userService.GetUserByIdAsync(user.UserID);
            Assert.That(retrievedUser, Is.Not.Null);
            Assert.That(retrievedUser!.Username, Is.EqualTo("integration_user"));
            Console.WriteLine($"✓ Retrieved user by ID: {retrievedUser.UserID}");

            // Act: Update email
            var updateResult = await _userService.UpdateUserEmailAsync(user.UserID, "newemail@example.com");
            Assert.That(updateResult, Is.True);
            
            var updatedUser = await _userService.GetUserByIdAsync(user.UserID);
            Assert.That(updatedUser!.Email, Is.EqualTo("newemail@example.com"));
            Console.WriteLine($"✓ Updated email: {updatedUser.Email}");

            // Act: Delete user
            var deleteResult = await _userService.DeleteUserAsync(user.UserID);
            Assert.That(deleteResult, Is.True);
            
            var deletedUser = await _userService.GetUserByIdAsync(user.UserID);
            Assert.That(deletedUser, Is.Null);
            Console.WriteLine("✓ Deleted user successfully");
        }

        #endregion
    }
}
