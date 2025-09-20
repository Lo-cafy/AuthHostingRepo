using AuthService.Domain.Entities;

namespace AuthService.Infrastructure.Interfaces
{
    public interface IUserCredentialRepository
    {
        Task<UserCredential?> GetByEmailAsync(string email);
        Task<UserCredential?> GetByUserIdAsync(int userId);
        Task<UserCredential> CreateAsync(UserCredential credential);
        Task UpdateAsync(UserCredential credential);
        Task<bool> EmailExistsAsync(string email);
    }
}