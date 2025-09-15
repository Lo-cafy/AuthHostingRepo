namespace AuthService.Domain.Entities
{
    public class UserCredential
    {
        public long CredentialId { get; set; }
        public Guid UserId { get; set; }
        public string Email { get; set; } = string.Empty;
        public string PasswordHash { get; set; } = string.Empty;
        public string PasswordSalt { get; set; } = string.Empty;
        public string Role { get; set; } = "customer";
        public bool IsActive { get; set; } = true;
        public int FailedAttempts { get; set; } = 0;
        public DateTime? LockedUntil { get; set; }
        public DateTime? PasswordChangedAt { get; set; }
        public DateTime CreatedAt { get; set; }
        public DateTime UpdatedAt { get; set; }
        public bool MustChangePassword { get; set; }
    }
}