using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using System.Linq;
using Microsoft.EntityFrameworkCore;
using AuthService.Domain.Entities;
using AuthService.Infrastructure.Data;
using AuthService.Infrastructure.Interfaces;

namespace AuthService.Infrastructure.Repositories
{
    public class OAuthRepository : IOAuthRepository
    {
        private readonly AuthDbContext _context;

        public OAuthRepository(AuthDbContext context)
        {
            _context = context;
        }

        public async Task<OAuthProvider> GetProviderAsync(string provider)
        {
            return await _context.OAuthProviders
                .FirstOrDefaultAsync(p => p.ProviderName.ToLower() == provider.ToLower() && p.IsActive);
        }

        public async Task<OAuthConnection> GetConnectionAsync(Guid providerId, string providerUserId)
        {
            return await _context.OAuthConnections
                .Include(c => c.Provider)
                .FirstOrDefaultAsync(c => c.ProviderId == providerId && c.ProviderUserId == providerUserId);
        }

        public async Task<OAuthConnection> CreateConnectionAsync(OAuthConnection connection)
        {
            _context.OAuthConnections.Add(connection);
            await _context.SaveChangesAsync();
            return connection;
        }

        public async Task UpdateConnectionAsync(OAuthConnection connection)
        {
            _context.OAuthConnections.Update(connection);
            await _context.SaveChangesAsync();
        }

        public async Task<IEnumerable<OAuthConnection>> GetUserConnectionsAsync(Guid userId)
        {
            return await _context.OAuthConnections
                .Include(c => c.Provider)
                .Where(c => c.UserId == userId)
                .OrderByDescending(c => c.LastUsedAt)
                .ToListAsync();
        }

        public async Task<OAuthConnection> GetConnectionByProviderEmailAsync(string provider, string email)
        {
            return await _context.OAuthConnections
                .Include(c => c.Provider)
                .FirstOrDefaultAsync(c =>
                    c.Provider.ProviderName.ToLower() == provider.ToLower() &&
                    c.ProviderEmail.ToLower() == email.ToLower());
        }
    }
}