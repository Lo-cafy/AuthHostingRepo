using System;
using System.Threading.Tasks;
using AuthService.Domain.Entities;

namespace AuthService.Infrastructure.Interfaces
{
    public interface IUserCredentialRepository
    {
        Task<dynamic> RegisterWithPasswordAsync(
            Guid userId,
            string email,
            string password,
            string roleName = "customer",
            string ipAddress = null,
            string userAgent = null,
            Guid? requestId = null);

        Task<dynamic> AuthenticatePasswordAsync(
            string email,
            string password,
            object deviceInfo = null,
            Guid? requestId = null);

        Task<UserCredential> GetByEmailAsync(string email);
        Task<UserCredential> GetByUserIdAsync(Guid userId);
        Task<bool> UpdateFailedAttemptsAsync(long credentialId, int failedAttempts, DateTime? lockedUntil);
        Task<bool> UpdatePasswordAsync(Guid userId, string newPasswordHash, string newPasswordSalt);
        Task<UserCredential> CreateAsync(UserCredential credential);
        Task<bool> UpdateAsync(UserCredential credential);
    }
}