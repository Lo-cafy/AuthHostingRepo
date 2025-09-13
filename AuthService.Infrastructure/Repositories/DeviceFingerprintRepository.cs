using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.EntityFrameworkCore;
using AuthService.Domain.Entities;
using AuthService.Infrastructure.Data;
using AuthService.Infrastructure.Interfaces;

namespace AuthService.Infrastructure.Repositories
{
    public class DeviceFingerprintRepository : IDeviceFingerprintRepository
    {
        private readonly AuthDbContext _context;

        public DeviceFingerprintRepository(AuthDbContext context)
        {
            _context = context;
        }

        public async Task<DeviceFingerprint> GetByIdAsync(Guid fingerprintId)
        {
            return await _context.DeviceFingerprints
                .FirstOrDefaultAsync(d => d.FingerprintId == fingerprintId);
        }

        public async Task<DeviceFingerprint> GetByDeviceIdAsync(string deviceId)
        {
            return await _context.DeviceFingerprints
                .FirstOrDefaultAsync(d => d.DeviceId == deviceId);
        }

        public async Task<IEnumerable<DeviceFingerprint>> GetByUserIdAsync(Guid userId)
        {
            return await _context.DeviceFingerprints
                .Where(d => d.UserId == userId)
                .OrderByDescending(d => d.LastUsedAt)
                .ToListAsync();
        }

        public async Task<DeviceFingerprint> CreateAsync(DeviceFingerprint deviceFingerprint)
        {
            deviceFingerprint.CreatedAt = DateTime.UtcNow;
            deviceFingerprint.LastUsedAt = DateTime.UtcNow;

            _context.DeviceFingerprints.Add(deviceFingerprint);
            await _context.SaveChangesAsync();

            return deviceFingerprint;
        }

        public async Task UpdateAsync(DeviceFingerprint deviceFingerprint)
        {
            deviceFingerprint.LastUsedAt = DateTime.UtcNow;

            _context.DeviceFingerprints.Update(deviceFingerprint);
            await _context.SaveChangesAsync();
        }

        public async Task<bool> DeleteAsync(Guid fingerprintId)
        {
            var deviceFingerprint = await GetByIdAsync(fingerprintId);
            if (deviceFingerprint == null)
                return false;

            _context.DeviceFingerprints.Remove(deviceFingerprint);
            await _context.SaveChangesAsync();
            return true;
        }

        public async Task<bool> ExistsAsync(string deviceId)
        {
            return await _context.DeviceFingerprints
                .AnyAsync(d => d.DeviceId == deviceId);
        }

        public async Task<bool> ValidateFingerprintAsync(Guid userId, string fingerprintHash)
        {
            return await _context.DeviceFingerprints
                .AnyAsync(d => d.UserId == userId &&
                              d.FingerprintHash == fingerprintHash);
        }

        public async Task<bool> UpdateTrustStatusAsync(Guid fingerprintId, bool isTrusted)
        {
            var deviceFingerprint = await GetByIdAsync(fingerprintId);
            if (deviceFingerprint == null)
                return false;

            deviceFingerprint.IsTrusted = isTrusted;
            deviceFingerprint.LastTrustUpdateAt = DateTime.UtcNow;

            await UpdateAsync(deviceFingerprint);
            return true;
        }

        public async Task<IEnumerable<DeviceFingerprint>> GetTrustedDevicesAsync(Guid userId)
        {
            return await _context.DeviceFingerprints
                .Where(d => d.UserId == userId && d.IsTrusted)
                .OrderByDescending(d => d.LastUsedAt)
                .ToListAsync();
        }
    }
}