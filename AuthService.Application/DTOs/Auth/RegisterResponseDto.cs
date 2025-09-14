using System;

namespace AuthService.Application.DTOs.Auth
{
    public class RegisterResponseDto
    {
        public bool Success { get; set; }
        public Guid UserId { get; set; }
        public string Email { get; set; }
        public string VerificationToken { get; set; }
        public string Message { get; set; }
    }
}