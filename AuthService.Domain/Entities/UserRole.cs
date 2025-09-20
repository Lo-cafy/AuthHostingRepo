using System;

namespace AuthService.Domain.Entities
{
    public class UserRole
    {
        public int AssignmentId { get; set; }
        public int UserId { get; set; }
        public int RoleId { get; set; }
        public int? AssignedBy { get; set; }
        public DateTime AssignedAt { get; set; }
        public DateTime? ExpiresAt { get; set; }
        public bool IsActive { get; set; }

        public Role Role { get; set; }
    }
}