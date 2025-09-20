using AuthService.Infrastructure.Interfaces;

namespace AuthService.Infrastructure.Repositories
{
    public class UserRepository : IUserRepository
    {
        public async Task<bool> Exists(string userId)
        {
            return true;
        }
    }
}