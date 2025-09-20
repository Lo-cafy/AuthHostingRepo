using System;
using System.ComponentModel.DataAnnotations;

namespace AuthService.Application.DTOs.Role
{
    public class AssignRoleDto
    {
        [Required]
        public int UserId { get; set; }

        [Required]
        public int RoleId { get; set; }

        public int? AssignedBy { get; set; }

        public DateTime? ExpiresAt { get; set; }
    }
}