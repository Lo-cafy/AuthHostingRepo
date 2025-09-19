using System;
using System.Security.Cryptography;
using System.Text;
using AuthService.Application.DTOs.Common;
using AuthService.Application.Interfaces;

namespace AuthService.Application.Services
{
    public class DigitalFingerprintService : IDigitalFingerprintService
    {
        public string GenerateFingerprint(DeviceInfoDto deviceInfo)
        {
            if (deviceInfo == null)
                return GenerateDefaultFingerprint();

            var fingerprintData = new StringBuilder();

            // Add device-specific data
            fingerprintData.Append(deviceInfo.IpAddress ?? "unknown");
            fingerprintData.Append("|");
            fingerprintData.Append(deviceInfo.UserAgent ?? "unknown");

            // Generate hash
            using (var sha256 = SHA256.Create())
            {
                var hashBytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(fingerprintData.ToString()));
                return Convert.ToBase64String(hashBytes);
            }
        }

        public bool ValidateFingerprint(string fingerprint, DeviceInfoDto deviceInfo)
        {
            var expectedFingerprint = GenerateFingerprint(deviceInfo);
            return fingerprint == expectedFingerprint;
        }

        private string GenerateDefaultFingerprint()
        {
            return Convert.ToBase64String(Encoding.UTF8.GetBytes("default-fingerprint"));
        }
    }
}