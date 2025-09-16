using System.ComponentModel.DataAnnotations;

namespace AuthService.Application.DTOs.Auth
{
    public class RefreshTokenRequestDto
    {
        [Required]
        public string RefreshToken { get; set; }
        public string? IpAddress { get; internal set; }
        public string? UserAgent { get; internal set; }
    }
}