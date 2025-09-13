using System.ComponentModel.DataAnnotations;

namespace AuthService.Application.DTOs.Account
{
    public class ForgotPasswordRequestDto
    {
        [Required]
        [EmailAddress]
        public string Email { get; set; }
    }
}