using System;
using System.ComponentModel.DataAnnotations;

namespace AuthService.Application.DTOs.Role
{
    public class AssignRoleDto
    {
        [Required]
        public Guid UserId { get; set; }

        [Required]
        public Guid RoleId { get; set; }

        public Guid? AssignedBy { get; set; }

        public DateTime? ExpiresAt { get; set; }
    }
}