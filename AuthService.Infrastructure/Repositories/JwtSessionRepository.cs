using System;
using System.Collections.Generic;  // Add this
using System.Threading.Tasks;
using System.Linq;  // Add this
using Microsoft.EntityFrameworkCore;
using AuthService.Domain.Entities;
using AuthService.Infrastructure.Data;
using AuthService.Infrastructure.Interfaces;

namespace AuthService.Infrastructure.Repositories
{
    public class JwtSessionRepository : IJwtSessionRepository
    {
        private readonly AuthDbContext _context;

        public JwtSessionRepository(AuthDbContext context)
        {
            _context = context;
        }

        public async Task<JwtSession> GetByJtiAsync(string jti)
        {
            return await _context.JwtSessions
                .FirstOrDefaultAsync(x => x.Jti == jti && x.IsActive);
        }

        public async Task<JwtSession> GetByRefreshJtiAsync(string refreshJti)
        {
            return await _context.JwtSessions
                .FirstOrDefaultAsync(x => x.RefreshJti == refreshJti && x.IsActive);
        }

        // Add this new method
        public async Task<IEnumerable<JwtSession>> GetActiveSessionsByUserIdAsync(Guid userId)
        {
            return await _context.JwtSessions
                .Where(x => x.UserId == userId &&
                           x.IsActive &&
                           x.ExpiresAt > DateTime.UtcNow)
                .ToListAsync();
        }

        public async Task<JwtSession> CreateAsync(JwtSession session)
        {
            _context.JwtSessions.Add(session);
            await _context.SaveChangesAsync();
            return session;
        }

        public async Task UpdateAsync(JwtSession session)
        {
            _context.JwtSessions.Update(session);
            await _context.SaveChangesAsync();
        }
    }
}