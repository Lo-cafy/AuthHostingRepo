using System;
using System.ComponentModel.DataAnnotations;

namespace AuthService.Application.DTOs.Account
{
    public class ChangePasswordDto
    {
        [Required]
        public int UserId { get; set; }

        [Required]
        public string CurrentPassword { get; set; }

        [Required]
        [MinLength(12)]
        public string NewPassword { get; set; }

        [Required]
        [Compare("NewPassword")]
        public string ConfirmNewPassword { get; set; }
    }
}