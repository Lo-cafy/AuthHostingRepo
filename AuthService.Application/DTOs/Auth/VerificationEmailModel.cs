using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace AuthService.Application.DTOs.Auth
{
    public class PasswordResetEmailModel
    {
        public string UserName { get; set; } = string.Empty;
        public string ResetLink { get; set; } = string.Empty;
    }
}