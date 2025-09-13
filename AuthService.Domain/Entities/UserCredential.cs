using System;

namespace AuthService.Domain.Entities
{
    public class UserCredential
    {
        public int CredentialId { get; set; }
        public Guid UserId { get; set; }
        public string Email { get; set; }
        public string PasswordHash { get; set; }
        public int FailedAttempts { get; set; }
        public DateTime? LockedUntil { get; set; }
        public DateTime PasswordChangedAt { get; set; }
        public bool MustChangePassword { get; set; }
        public DateTime CreatedAt { get; set; }
        public DateTime UpdatedAt { get; set; }
        public bool IsActive { get; set; }
        public string Role { get; set; }
    }
}