using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using Dapper;
using AuthService.Domain.Entities;
using AuthService.Infrastructure.Data.Interfaces;
using AuthService.Infrastructure.Interfaces;

namespace AuthService.Infrastructure.Repositories
{
    public class DeviceFingerprintRepository : BaseRepository, IDeviceFingerprintRepository
    {
        public DeviceFingerprintRepository(Data.Interfaces.IDbConnectionFactory connectionFactory)
            : base(connectionFactory)
        {
        }

        public async Task<DeviceFingerprint> GetByIdAsync(int fingerprintId)
        {
            const string sql = @"
                SELECT * FROM auth.device_fingerprints 
                WHERE fingerprint_id = @FingerprintId";

            return await ExecuteAsync<DeviceFingerprint>(sql, new { FingerprintId = fingerprintId });
        }

        public async Task<DeviceFingerprint> GetByDeviceIdAsync(string deviceId)
        {
            const string sql = @"
                SELECT * FROM auth.device_fingerprints 
                WHERE device_id = @DeviceId";

            return await ExecuteAsync<DeviceFingerprint>(sql, new { DeviceId = deviceId });
        }

        public async Task<IEnumerable<DeviceFingerprint>> GetByUserIdAsync(int userId)
        {
            const string sql = @"
                SELECT * FROM auth.device_fingerprints 
                WHERE user_id = @UserId 
                ORDER BY last_used_at DESC";

            return await QueryAsync<DeviceFingerprint>(sql, new { UserId = userId });
        }

        public async Task<DeviceFingerprint> CreateAsync(DeviceFingerprint deviceFingerprint)
        {
            const string sql = @"
                INSERT INTO auth.device_fingerprints 
                (fingerprint_id, user_id, device_id, device_name, device_type, 
                 fingerprint_hash, created_at, last_used_at, is_trusted)
                VALUES 
                (@FingerprintId, @UserId, @DeviceId, @DeviceName, @DeviceType,
                 @FingerprintHash, @CreatedAt, @LastUsedAt, @IsTrusted)
                RETURNING *";

            deviceFingerprint.CreatedAt = DateTime.UtcNow;
            deviceFingerprint.LastUsedAt = DateTime.UtcNow;

            return await ExecuteAsync<DeviceFingerprint>(sql, deviceFingerprint);
        }

        public async Task UpdateAsync(DeviceFingerprint deviceFingerprint)
        {
            const string sql = @"
                UPDATE auth.device_fingerprints 
                SET device_name = @DeviceName,
                    device_type = @DeviceType,
                    fingerprint_hash = @FingerprintHash,
                    last_used_at = @LastUsedAt,
                    is_trusted = @IsTrusted
                WHERE fingerprint_id = @FingerprintId";

            deviceFingerprint.LastUsedAt = DateTime.UtcNow;
            await ExecuteCommandAsync(sql, deviceFingerprint);
        }

        public async Task<bool> DeleteAsync(int fingerprintId)
        {
            const string sql = @"
                DELETE FROM auth.device_fingerprints 
                WHERE fingerprint_id = @FingerprintId";

            var rowsAffected = await ExecuteCommandAsync(sql, new { FingerprintId = fingerprintId });
            return rowsAffected > 0;
        }

        public async Task<bool> ExistsAsync(string deviceId)
        {
            const string sql = @"
                SELECT COUNT(1) FROM auth.device_fingerprints 
                WHERE device_id = @DeviceId";

            var count = await ExecuteScalarAsync<int>(sql, new { DeviceId = deviceId });
            return count > 0;
        }

        public async Task<bool> ValidateFingerprintAsync(int userId, string fingerprintHash)
        {
            const string sql = @"
                SELECT COUNT(1) FROM auth.device_fingerprints 
                WHERE user_id = @UserId 
                AND fingerprint_hash = @FingerprintHash";

            var count = await ExecuteScalarAsync<int>(
                sql, new { UserId = userId, FingerprintHash = fingerprintHash });
            return count > 0;
        }

        public async Task<bool> UpdateTrustStatusAsync(int fingerprintId, bool isTrusted)
        {
            const string sql = @"
                UPDATE auth.device_fingerprints 
                SET is_trusted = @IsTrusted,
                    last_trust_update_at = @LastTrustUpdateAt
                WHERE fingerprint_id = @FingerprintId";

            var rowsAffected = await ExecuteCommandAsync(sql, new
            {
                FingerprintId = fingerprintId,
                IsTrusted = isTrusted,
                LastTrustUpdateAt = DateTime.UtcNow
            });

            return rowsAffected > 0;
        }

        public async Task<IEnumerable<DeviceFingerprint>> GetTrustedDevicesAsync(int userId)
        {
            const string sql = @"
                SELECT * FROM auth.device_fingerprints 
                WHERE user_id = @UserId 
                AND is_trusted = true 
                ORDER BY last_used_at DESC";

            return await QueryAsync<DeviceFingerprint>(sql, new { UserId = userId });
        }
    }
}