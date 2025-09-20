using System;

namespace AuthService.Application.DTOs.Auth.OAuth
{
    public class OAuthCallbackDto
    {
        public bool Success { get; set; }
        public string AccessToken { get; set; }
        public string RefreshToken { get; set; }
        public int UserId { get; set; }
        public string Email { get; set; }
        public bool IsNewUser { get; set; }
        public string Provider { get; set; }
    }
}