using System;

namespace AuthService.Domain.Entities
{
    public class DeviceFingerprint
    {
        public Guid FingerprintId { get; set; }
        public Guid UserId { get; set; }
        public string Browser { get; set; }
        public string UserAgent { get; set; }
        public string IpAddress { get; set; }
        public string ScreenResolution { get; set; }
        public string TimeZone { get; set; }
        public string Language { get; set; }
        public bool HasTouchScreen { get; set; }
        public string FingerprintHash { get; set; }
        public bool IsTrusted { get; set; }
        public DateTime CreatedAt { get; set; }
        public DateTime? LastUsedAt { get; set; }
        public DateTime? LastTrustUpdateAt { get; set; }
    }
}