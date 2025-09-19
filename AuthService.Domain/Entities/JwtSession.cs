using System;

namespace AuthService.Domain.Entities
{
    public class JwtSession
    {
        public Guid SessionId { get; set; }
        public Guid UserId { get; set; }
        public string Jti { get; set; }
        public string RefreshJti { get; set; }
        public string IpAddress { get; set; }
        public string UserAgent { get; set; }
        public string Location { get; set; }
        public DateTime CreatedAt { get; set; }
        public DateTime LastAccessedAt { get; set; }
        public DateTime ExpiresAt { get; set; }
        public bool IsActive { get; set; }
        public DateTime? RevokedAt { get; set; }
        public string RevokeReason { get; set; }
    }
}