using AuthService.Domain.Enums;
using System;
using System.Security.Claims;

namespace AuthService.Application.Interfaces
{
    public interface IJwtService
    {
        string GenerateAccessToken(Guid userId, string email, RoleTypeEnum role, string jti);
        string GenerateRefreshToken(Guid userId, string refreshJti);
        ClaimsPrincipal ValidateToken(string token);
        ClaimsPrincipal ValidateRefreshToken(string token);
    }
}