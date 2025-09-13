using System;
using System.Threading.Tasks;
using Microsoft.EntityFrameworkCore;
using AuthService.Domain.Entities;
using AuthService.Infrastructure.Data;
using AuthService.Infrastructure.Interfaces;

namespace AuthService.Infrastructure.Repositories
{
    public class UserCredentialRepository : IUserCredentialRepository
    {
        private readonly AuthDbContext _context;

        public UserCredentialRepository(AuthDbContext context)
        {
            _context = context;
        }

        public async Task<UserCredential> GetByEmailAsync(string email)
        {
            return await _context.UserCredentials
                .FirstOrDefaultAsync(x => x.Email.ToLower() == email.ToLower() && x.IsActive);
        }

        public async Task<UserCredential> GetByUserIdAsync(Guid userId)
        {
            return await _context.UserCredentials
                .FirstOrDefaultAsync(x => x.UserId == userId && x.IsActive);
        }

        public async Task<UserCredential> CreateAsync(UserCredential credential)
        {
            _context.UserCredentials.Add(credential);
            await _context.SaveChangesAsync();
            return credential;
        }

        public async Task UpdateAsync(UserCredential credential)
        {
            _context.UserCredentials.Update(credential);
            await _context.SaveChangesAsync();
        }

        public async Task<bool> EmailExistsAsync(string email)
        {
            return await _context.UserCredentials
                .AnyAsync(x => x.Email.ToLower() == email.ToLower());
        }
    }
}