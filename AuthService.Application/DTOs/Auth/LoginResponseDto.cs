using System;

namespace AuthService.Application.DTOs.Auth
{
    public class LoginResponseDto
    {
        public string AccessToken { get; set; }
        public string RefreshToken { get; set; }
        public int ExpiresIn { get; set; }
        public string TokenType { get; set; } = "Bearer";
        public Guid UserId { get; set; }
        public string Email { get; set; }
         public RoleTypeEnum Role { get; set; }
    }
}
