using System;

namespace AuthService.Domain.Entities
{
    public class OAuthProvider
    {
        public int ProviderId { get; set; }
        public string ProviderName { get; set; } = string.Empty;
        public string ClientId { get; set; } = string.Empty;
        public string ClientSecretEncrypted { get; set; } = string.Empty;
        public string AuthorizationUrl { get; set; } = string.Empty;
        public string TokenUrl { get; set; } = string.Empty;
        public string UserInfoUrl { get; set; } = string.Empty;
        public string[]? Scopes { get; set; }
        public bool IsActive { get; set; }
        public DateTime CreatedAt { get; set; }
        public DateTime UpdatedAt { get; set; }
    }
}