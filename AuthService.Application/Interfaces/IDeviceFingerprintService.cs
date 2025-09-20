using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using AuthService.Application.DTOs.Auth;

namespace AuthService.Application.Interfaces
{
    public interface IDeviceFingerprintService
    {
        Task<bool> RegisterDeviceAsync(int userId, DeviceFingerprintDto deviceInfo);
        Task<string> GenerateFingerprintAsync(DeviceFingerprintDto deviceInfo);
        Task<bool> ValidateFingerprintAsync(int userId, string fingerprintHash);
        Task<bool> TrustDeviceAsync(int userId, TrustDeviceDto trustInfo);
        Task<IEnumerable<DeviceFingerprintDto>> GetUserDevicesAsync(int userId);
    }
}