using System;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.EntityFrameworkCore;
using AuthService.Domain.Entities;
using AuthService.Infrastructure.Data;
using AuthService.Infrastructure.Interfaces;

namespace AuthService.Infrastructure.Repositories
{
    public class LoginAttemptRepository : ILoginAttemptRepository
    {
        private readonly AuthDbContext _context;

        public LoginAttemptRepository(AuthDbContext context)
        {
            _context = context;
        }

        public async Task<int> GetRecentFailuresAsync(string fingerprint, int minutes)
        {
            var cutoffTime = DateTime.UtcNow.AddMinutes(-minutes);

            return await _context.LoginAttempts
                .Where(x => x.Fingerprint == fingerprint
                    && x.AttemptedAt > cutoffTime
                    && !x.Success)
                .CountAsync();
        }

        public async Task CreateAsync(LoginAttempt attempt)
        {
            _context.LoginAttempts.Add(attempt);
            await _context.SaveChangesAsync();
        }
    }
}