using System;

namespace AuthService.Application.DTOs.Auth
{
    public class RegisterResponseDto
    {
        public int UserId { get; set; }
        public string Email { get; set; }
        public string VerificationToken { get; set; }
        public string Message { get; set; }
        public bool Success { get; internal set; }
        public string ErrorCode { get; internal set; }
    }
}