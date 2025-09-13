using System;
using AuthService.Domain.Enums;

namespace AuthService.Domain.Entities
{
    public class SecurityToken
    {
        public Guid TokenId { get; set; }
        public Guid UserId { get; set; }
        public TokenTypeEnum TokenType { get; set; }
        public string TokenHash { get; set; }
        public DateTime ExpiresAt { get; set; }
        public DateTime? UsedAt { get; set; }
        public string Metadata { get; set; }
        public DateTime CreatedAt { get; set; }
    }
}