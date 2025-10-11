using AuthService.Domain.Enums;

namespace AuthService.Domain.Entities
{
    public class UserCredential
    {
        public long CredentialId { get; set; }
        public int UserId { get; set; }
        public string Email { get; set; } = string.Empty;
        public string PasswordHash { get; set; } = string.Empty;
        public string PasswordSalt { get; set; } = string.Empty;
        public RoleType Role { get; set; } 
        public bool IsActive { get; set; } = true;
        public int FailedAttempts { get; set; } = 0;
        public DateTime? LockedUntil { get; set; }
        public DateTime? PasswordChangedAt { get; set; }
        public DateTime CreatedAt { get; set; }
        public DateTime UpdatedAt { get; set; }
    }
}