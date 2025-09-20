using System;
using System.Security.Claims;
using AuthService.Domain.Enums;

namespace AuthService.Application.Interfaces
{
    public interface IJwtService
    {
        string GenerateAccessToken(int userId, string email, RoleTypeEnum role, string jti);
        string GenerateRefreshToken(int userId, string refreshJti);
        ClaimsPrincipal ValidateToken(string token);
        ClaimsPrincipal ValidateRefreshToken(string token);
    }
}