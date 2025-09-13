using AuthService.Application.Interfaces;

namespace AuthService.Application.Services
{
    public class SecurityService : ISecurityService
    {
        public async Task<bool> ValidateSecurityToken(string token)
        {
            // Implementation
            return true;
        }
    }
}