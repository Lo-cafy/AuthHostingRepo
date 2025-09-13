using System;

namespace AuthService.Application.DTOs.Auth
{
    public class LinkedAccountDto
    {
        public string Provider { get; set; }
        public string ProviderEmail { get; set; }
        public bool IsPrimary { get; set; }
        public DateTime ConnectedAt { get; set; }
        public DateTime? LastUsedAt { get; set; }
    }
}