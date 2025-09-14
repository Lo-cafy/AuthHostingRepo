using System;

namespace AuthService.Domain.Entities
{
    public class OAuthConnection
    {
        public Guid ConnectionId { get; set; }
        public Guid UserId { get; set; }
        public Guid ProviderId { get; set; }
        public string ProviderUserId { get; set; } = string.Empty;
        public string? ProviderEmail { get; set; }
        public Dictionary<string, object>? ProviderData { get; set; }
        public string? ProviderDataJson { get; set; }
        public string? AccessTokenEncrypted { get; set; }
        public string? RefreshTokenEncrypted { get; set; }
        public DateTime? TokenExpiresAt { get; set; }
        public bool IsPrimary { get; set; }
        public DateTime ConnectedAt { get; set; }
        public DateTime? LastUsedAt { get; set; }
        public bool IsActive { get; set; } = true;

        public virtual OAuthProvider? Provider { get; set; }
    }
}