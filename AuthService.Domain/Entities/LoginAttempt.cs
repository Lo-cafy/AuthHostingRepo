using System;
using AuthService.Domain.Enums;

namespace AuthService.Domain.Entities
{
    public class LoginAttempt
    {
        public int AttemptId { get; set; }
        public string Identifier { get; set; }
        public AuthProviderEnum AuthProvider { get; set; }
        public bool Success { get; set; }
        public string FailureReason { get; set; }
        public string IpAddress { get; set; }
        public string UserAgent { get; set; }
        public DateTime AttemptedAt { get; set; }
        public string Fingerprint { get; set; }
    }
}