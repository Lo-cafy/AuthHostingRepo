using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using AuthService.Domain.Entities;

namespace AuthService.Infrastructure.Interfaces
{
    public interface IDeviceFingerprintRepository
    {
        Task<DeviceFingerprint> GetByIdAsync(Guid fingerprintId);
        Task<DeviceFingerprint> GetByDeviceIdAsync(string deviceId);
        Task<IEnumerable<DeviceFingerprint>> GetByUserIdAsync(Guid userId);
        Task<DeviceFingerprint> CreateAsync(DeviceFingerprint deviceFingerprint);
        Task UpdateAsync(DeviceFingerprint deviceFingerprint);
        Task<bool> DeleteAsync(Guid fingerprintId);
        Task<bool> ExistsAsync(string deviceId);
        Task<bool> ValidateFingerprintAsync(Guid userId, string fingerprintHash);
        Task<bool> UpdateTrustStatusAsync(Guid fingerprintId, bool isTrusted);
        Task<IEnumerable<DeviceFingerprint>> GetTrustedDevicesAsync(Guid userId);
    }
}