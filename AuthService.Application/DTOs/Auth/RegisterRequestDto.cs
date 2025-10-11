using AuthService.Application.DTOs.Common;
using MediatR;
using System.ComponentModel.DataAnnotations;

namespace AuthService.Application.DTOs.Auth
{
    public class RegisterRequestDto
    {
        [Required]
        public int UserId { get; set; }


        [Required]
        [EmailAddress]
        public string Email { get; set; }

        [Required]
        [MinLength(8)]
        public string Password { get; set; }

        [Required]
        [MaxLength(10)]
        public string  PhoneNumber { get;set; }
        
        public int? ReferredBy { get; set; }

        public string? ClientIp { get; set; }

    }
}