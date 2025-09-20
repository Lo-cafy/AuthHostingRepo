using System;
using System.Threading.Tasks;
using AuthService.Domain.Entities;

namespace AuthService.Infrastructure.Interfaces
{
    public interface ISecurityTokenRepository
    {
        Task<SecurityToken> GetByTokenHashAsync(string tokenHash);
        Task<SecurityToken> CreateAsync(SecurityToken token);
        Task<bool> UpdateAsync(SecurityToken token);
        Task<bool> MarkAsUsedAsync(int tokenId);
    }
}