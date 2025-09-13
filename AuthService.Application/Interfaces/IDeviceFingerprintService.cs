using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using AuthService.Application.DTOs.Auth;

namespace AuthService.Application.Interfaces
{
    public interface IDeviceFingerprintService
    {
        Task<bool> RegisterDeviceAsync(Guid userId, DeviceFingerprintDto deviceInfo);
        Task<string> GenerateFingerprintAsync(DeviceFingerprintDto deviceInfo);
        Task<bool> ValidateFingerprintAsync(Guid userId, string fingerprintHash);
        Task<bool> TrustDeviceAsync(Guid userId, TrustDeviceDto trustInfo);
        Task<IEnumerable<DeviceFingerprintDto>> GetUserDevicesAsync(Guid userId);
    }
}