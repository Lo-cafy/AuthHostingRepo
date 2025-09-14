using AuthService.Domain.Enums;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace AuthService.Application.DTOs.Auth
{
    public class UserInfoDto
    {
        public Guid UserId { get; set; }
        public string Email { get; set; } = string.Empty;
        public bool IsEmailVerified { get; set; }
        public RoleTypeEnum Role { get; set; }
    }
}
