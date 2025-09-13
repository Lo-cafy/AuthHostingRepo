using System.ComponentModel.DataAnnotations;

namespace AuthService.Application.DTOs.Account
{
    public class VerifyEmailDto
    {
        [Required]
        public string Token { get; set; }
    }
}