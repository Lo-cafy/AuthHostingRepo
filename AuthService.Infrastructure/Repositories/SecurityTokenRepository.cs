using System.Threading.Tasks;
using Microsoft.EntityFrameworkCore;
using AuthService.Domain.Entities;
using AuthService.Infrastructure.Data;
using AuthService.Infrastructure.Interfaces;

namespace AuthService.Infrastructure.Repositories
{
    public class SecurityTokenRepository : ISecurityTokenRepository
    {
        private readonly AuthDbContext _context;

        public SecurityTokenRepository(AuthDbContext context)
        {
            _context = context;
        }

        public async Task<SecurityToken> GetByTokenHashAsync(string tokenHash)
        {
            return await _context.SecurityTokens
                .FirstOrDefaultAsync(x => x.TokenHash == tokenHash);
        }

        public async Task<SecurityToken> CreateAsync(SecurityToken token)
        {
            _context.SecurityTokens.Add(token);
            await _context.SaveChangesAsync();
            return token;
        }

        public async Task UpdateAsync(SecurityToken token)
        {
            _context.SecurityTokens.Update(token);
            await _context.SaveChangesAsync();
        }
    }
}