using System;

namespace AuthService.Domain.Entities
{
    public class OAuthProvider
    {
        public Guid ProviderId { get; set; }
        public string ProviderName { get; set; }
        public string ClientId { get; set; }
        public string ClientSecretEncrypted { get; set; }
        public string AuthorizationUrl { get; set; }
        public string TokenUrl { get; set; }
        public string UserInfoUrl { get; set; }
        public string[] Scopes { get; set; }
        public bool IsActive { get; set; }
        public DateTime CreatedAt { get; set; }
    }
}