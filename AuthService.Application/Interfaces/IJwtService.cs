using System;
using System.Security.Claims;

namespace AuthService.Application.Interfaces
{
    public interface IJwtService
    {
        string GenerateAccessToken(Guid userId, string email, string[] roles, string sessionJti);
        string GenerateRefreshToken(Guid userId, string refreshJti);
        ClaimsPrincipal ValidateToken(string token);
        ClaimsPrincipal ValidateRefreshToken(string token);
    }
}