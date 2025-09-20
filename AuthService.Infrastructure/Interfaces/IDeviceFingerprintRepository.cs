using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using AuthService.Domain.Entities;

namespace AuthService.Infrastructure.Interfaces
{
    public interface IDeviceFingerprintRepository
    {
        Task<DeviceFingerprint> GetByIdAsync(int fingerprintId);
        Task<DeviceFingerprint> GetByDeviceIdAsync(string deviceId);
        Task<IEnumerable<DeviceFingerprint>> GetByUserIdAsync(int userId);
        Task<DeviceFingerprint> CreateAsync(DeviceFingerprint deviceFingerprint);
        Task UpdateAsync(DeviceFingerprint deviceFingerprint);
        Task<bool> DeleteAsync(int fingerprintId);
        Task<bool> ExistsAsync(string deviceId);
        Task<bool> ValidateFingerprintAsync(int userId, string fingerprintHash);
        Task<bool> UpdateTrustStatusAsync(int fingerprintId, bool isTrusted);
        Task<IEnumerable<DeviceFingerprint>> GetTrustedDevicesAsync(int userId);
    }
}