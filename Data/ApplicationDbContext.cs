using Microsoft.EntityFrameworkCore;
using Secure.Models;

namespace Secure.Data
{
    /// <summary>
    /// Database context for SafeVault application
    /// Uses Entity Framework Core for secure, parameterized database access
    /// </summary>
    public class ApplicationDbContext : DbContext
    {
        public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options)
            : base(options)
        {
        }

        public DbSet<User> Users { get; set; }

        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            base.OnModelCreating(modelBuilder);

            // Configure User entity
            modelBuilder.Entity<User>(entity =>
            {
                entity.ToTable("Users");
                entity.HasKey(e => e.UserID);
                entity.HasIndex(e => e.Username).IsUnique();
                entity.HasIndex(e => e.Email).IsUnique();
                entity.Property(e => e.Username).IsRequired().HasMaxLength(50);
                entity.Property(e => e.Email).IsRequired().HasMaxLength(100);
                entity.Property(e => e.PasswordHash).IsRequired();
                entity.Property(e => e.Role).IsRequired().HasDefaultValue(UserRole.User);
                entity.Property(e => e.IsActive).HasDefaultValue(true);
                entity.Property(e => e.FailedLoginAttempts).HasDefaultValue(0);
                entity.Property(e => e.CreatedAt).HasDefaultValueSql("GETUTCDATE()");
            });

            // Seed initial admin user
            SeedData(modelBuilder);
        }

        private void SeedData(ModelBuilder modelBuilder)
        {
            // SECURITY: Create default admin account with hashed password
            // Password: Admin@123 (should be changed after first login in production)
            modelBuilder.Entity<User>().HasData(
                new User
                {
                    UserID = 1,
                    Username = "admin",
                    Email = "admin@safevault.com",
                    // Hash for "Admin@123"
                    PasswordHash = "$2a$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewY5GyYIpSRelGyG",
                    Role = UserRole.Admin,
                    IsActive = true,
                    FailedLoginAttempts = 0,
                    CreatedAt = DateTime.UtcNow
                }
            );
        }
    }
}
