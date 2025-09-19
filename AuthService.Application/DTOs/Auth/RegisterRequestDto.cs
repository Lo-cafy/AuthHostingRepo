//using AuthService.Application.DTOs.Common;
//using System.ComponentModel.DataAnnotations;

//namespace AuthService.Application.DTOs.Auth
//{
//    public class RegisterRequestDto
//    {
//        [Required]
//        [EmailAddress]
//        public string Email { get; set; }

//        [Required]
//        [MinLength(12)]
//        public string Password { get; set; }

//        [Required]
//        [Compare("Password")]
//        public string ConfirmPassword { get; set; }

//    }
//}