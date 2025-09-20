using System;
using System.Threading.Tasks;
using AuthService.Domain.Entities;

namespace AuthService.Infrastructure.Interfaces
{
    public interface IOAuthRepository
    {
        Task<OAuthProvider> GetProviderAsync(string providerName);
        Task<OAuthConnection> GetConnectionAsync(int providerId, string providerUserId);
        Task<OAuthConnection> CreateConnectionAsync(OAuthConnection connection);
        Task<IEnumerable<OAuthConnection>> GetUserConnectionsAsync(int userId);
        Task UpdateConnectionAsync(OAuthConnection connection);
        Task<OAuthConnection> GetConnectionByProviderEmailAsync(string provider, string email);
    }
}