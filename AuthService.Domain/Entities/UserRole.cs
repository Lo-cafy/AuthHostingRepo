using System;

namespace AuthService.Domain.Entities
{
    public class UserRole
    {
        public Guid AssignmentId { get; set; }
        public Guid UserId { get; set; }
        public Guid RoleId { get; set; }
        public Guid? AssignedBy { get; set; }
        public DateTime AssignedAt { get; set; }
        public DateTime? ExpiresAt { get; set; }
        public bool IsActive { get; set; }

        public Role Role { get; set; }
    }
}