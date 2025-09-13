using System.ComponentModel.DataAnnotations;
using AuthService.Application.DTOs.Common;

namespace AuthService.Application.DTOs.Auth
{
    public class LoginRequestDto
    {
        [Required]
        [EmailAddress]
        public string Email { get; set; }

        [Required]
        public string Password { get; set; }

        public DeviceInfoDto DeviceInfo { get; set; }
    }
}