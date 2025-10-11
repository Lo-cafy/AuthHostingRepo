using AuthService.Domain.Entities;

namespace AuthService.Infrastructure.Interfaces
{
    public interface IUserCredentialRepository
    {
        Task<UserCredential?> GetByEmailAsync(string email);
        Task<UserCredential?> GetByUserIdAsync(int userId);
        Task<UserCredential> CreateAsync(UserCredential credential);
        Task<(int UserId, int CredentialId)> RegisterUserEnhancedAsync( int userId, string email,string passwordHash,string passwordSalt,
                                                                         string role, string? phoneNumber, int? referredBy,string createdIp);
        Task UpdateAsync(UserCredential credential);
        Task<bool> EmailExistsAsync(string email);
    }
}