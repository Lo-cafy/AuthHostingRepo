using AuthService.Domain.Enums;
using System;

namespace AuthService.Application.DTOs.Auth
{
    public class LoginResponseDto
    {
        public string AccessToken { get; set; } = string.Empty;
        public string RefreshToken { get; set; } = string.Empty;
        public Double ExpiresIn { get; set; }
        public DateTime ExpiresAt { get; set; }
        public UserInfoDto User { get; set; } = new();
        public string Role { get; set; } = "customer";  
    }
}