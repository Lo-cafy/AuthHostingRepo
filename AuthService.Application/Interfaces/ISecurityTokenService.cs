using System;
using System.Threading.Tasks;
using AuthService.Domain.Enums;

namespace AuthService.Application.Interfaces
{
    public interface ISecurityTokenService
    {
        Task<string> GenerateTokenAsync(int userId, TokenTypeEnum tokenType);
        Task<bool> ValidateTokenAsync(string token, TokenTypeEnum tokenType);
        Task<bool> RevokeTokenAsync(string token);
    }
}