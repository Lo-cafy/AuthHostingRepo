using System.ComponentModel.DataAnnotations;

namespace AuthService.Application.DTOs.Auth
{
    public class RefreshTokenRequestDto
    {
        [Required]
        public string RefreshToken { get; set; }
    }
}