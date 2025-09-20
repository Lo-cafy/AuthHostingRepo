using System;

namespace AuthService.Application.DTOs.Auth
{
    public class TrustDeviceDto
    {
        public int FingerprintId { get; set; }
        public bool Trust { get; set; }
    }
}