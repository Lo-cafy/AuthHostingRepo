using AuthService.Application.DTOs.Common;

namespace AuthService.Application.Interfaces
{
    public interface IDigitalFingerprintService
    {
        string GenerateFingerprint(DeviceInfoDto deviceInfo);
        bool ValidateFingerprint(string fingerprint, DeviceInfoDto deviceInfo);
    }
}