using AuthService.Application.DTOs.Enum;
using System;

namespace AuthService.Application.DTOs.Auth
{
    public class AuthResultDto
    {
        public bool Success { get; set; }
        public int UserId { get; set; }
        public string AccessToken { get; set; }
        public string RefreshToken { get; set; }
        public int ExpiresIn { get; set; }
        public string TokenType { get; set; }
        public bool IsNewUser { get; set; }
        public string Error { get; set; }
        public string Message { get; set; }
        public List<RoleTypeEnum> Roles { get; set; }
        public object Email { get; internal set; }
    }
}