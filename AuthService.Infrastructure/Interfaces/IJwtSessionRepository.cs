using System;
using System.Threading.Tasks;
using AuthService.Domain.Entities;

namespace AuthService.Infrastructure.Interfaces
{
    public interface IJwtSessionRepository
    {
        Task<JwtSession> GetByJtiAsync(string jti);
        Task<JwtSession> GetByRefreshJtiAsync(string refreshJti);
        Task<JwtSession> CreateAsync(JwtSession session);
        Task<IEnumerable<JwtSession>> GetActiveSessionsByUserIdAsync(Guid userId);
        Task UpdateAsync(JwtSession session);
    }
}