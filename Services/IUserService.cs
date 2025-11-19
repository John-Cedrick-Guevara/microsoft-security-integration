using Secure.Models;

namespace Secure.Services
{
    /// <summary>
    /// Interface for secure user management operations
    /// </summary>
    public interface IUserService
    {
        Task<User?> CreateUserAsync(string username, string email);
        Task<User?> GetUserByIdAsync(int userId);
        Task<User?> GetUserByUsernameAsync(string username);
        Task<List<User>> GetAllUsersAsync(int pageNumber = 1, int pageSize = 10);
        Task<bool> UpdateUserEmailAsync(int userId, string newEmail);
        Task<bool> DeleteUserAsync(int userId);
    }
}
