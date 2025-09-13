using System;

namespace AuthService.Application.DTOs.Role
{
    public class RoleDto
    {
        public Guid RoleId { get; set; }
        public string RoleName { get; set; }
        public string RoleType { get; set; }
        public string Description { get; set; }
    }
}