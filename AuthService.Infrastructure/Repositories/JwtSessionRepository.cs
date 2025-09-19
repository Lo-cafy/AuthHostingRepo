using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using Dapper;
using AuthService.Domain.Entities;
using AuthService.Infrastructure.Data.Interfaces;
using AuthService.Infrastructure.Interfaces;
using Newtonsoft.Json;

namespace AuthService.Infrastructure.Repositories
{
    public class JwtSessionRepository : BaseRepository, IJwtSessionRepository
    {
        public JwtSessionRepository(IDbConnectionFactory connectionFactory)
            : base(connectionFactory)
        {
        }

        public async Task<JwtSession> GetByJtiAsync(string jti)
        {
            const string sql = @"
                SELECT 
                    session_id as SessionId,
                    user_id as UserId,
                    jti as Jti,
                    refresh_jti as RefreshJti,
                    device_id as DeviceId,
                    device_name as DeviceName,
                    device_type as DeviceType,
                    ip_address as IpAddress,
                    user_agent as UserAgent,
                    location as Location,
                    created_at as CreatedAt,
                    last_accessed_at as LastAccessedAt,
                    expires_at as ExpiresAt,
                    is_active as IsActive,
                    revoked_at as RevokedAt,
                    revoke_reason as RevokeReason
                FROM auth.jwt_sessions 
                WHERE jti = @jti AND is_active = true";

            return await ExecuteAsync<JwtSession>(sql, new { jti });
        }

        public async Task<JwtSession> GetByRefreshJtiAsync(string refreshJti)
        {
            const string sql = @"
                SELECT 
                    session_id as SessionId,
                    user_id as UserId,
                    jti as Jti,
                    refresh_jti as RefreshJti,
                    device_id as DeviceId,
                    device_name as DeviceName,
                    device_type as DeviceType,
                    ip_address as IpAddress,
                    user_agent as UserAgent,
                    location as Location,
                    created_at as CreatedAt,
                    last_accessed_at as LastAccessedAt,
                    expires_at as ExpiresAt,
                    is_active as IsActive,
                    revoked_at as RevokedAt,
                    revoke_reason as RevokeReason
                FROM auth.jwt_sessions 
                WHERE refresh_jti = @refreshJti AND is_active = true";

            return await ExecuteAsync<JwtSession>(sql, new { refreshJti });
        }

        public async Task<JwtSession> CreateAsync(JwtSession session)
        {
            const string sql = @"
                INSERT INTO auth.jwt_sessions (
                    session_id, user_id, jti, refresh_jti, device_id, 
                    device_name, device_type, ip_address, user_agent, 
                    location, created_at, last_accessed_at, expires_at, is_active
                ) VALUES (
                    @SessionId, @UserId, @Jti, @RefreshJti, @DeviceId,
                    @DeviceName, @DeviceType, @IpAddress::inet, @UserAgent,
                    @Location::jsonb, @CreatedAt, @LastAccessedAt, @ExpiresAt, @IsActive
                ) RETURNING 
                    session_id as SessionId,
                    user_id as UserId,
                    jti as Jti,
                    refresh_jti as RefreshJti,
                    device_id as DeviceId,
                    device_name as DeviceName,
                    device_type as DeviceType,
                    ip_address as IpAddress,
                    user_agent as UserAgent,
                    location as Location,
                    created_at as CreatedAt,
                    last_accessed_at as LastAccessedAt,
                    expires_at as ExpiresAt,
                    is_active as IsActive";

            var parameters = new DynamicParameters(session);
            parameters.Add("Location", JsonConvert.SerializeObject(session.Location ?? "{}"));

            return await ExecuteAsync<JwtSession>(sql, parameters);
        }

        public async Task UpdateAsync(JwtSession session)
        {
            const string sql = @"
                UPDATE auth.jwt_sessions 
                SET last_accessed_at = @LastAccessedAt,
                    is_active = @IsActive,
                    revoked_at = @RevokedAt,
                    revoke_reason = @RevokeReason
                WHERE session_id = @SessionId";

            await ExecuteCommandAsync(sql, session);
        }

        public async Task<IEnumerable<JwtSession>> GetActiveSessionsByUserIdAsync(Guid userId)
        {
            const string sql = @"
                SELECT 
                    session_id as SessionId,
                    user_id as UserId,
                    jti as Jti,
                    refresh_jti as RefreshJti,
                    device_id as DeviceId,
                    device_name as DeviceName,
                    device_type as DeviceType,
                    ip_address as IpAddress,
                    user_agent as UserAgent,
                    location as Location,
                    created_at as CreatedAt,
                    last_accessed_at as LastAccessedAt,
                    expires_at as ExpiresAt,
                    is_active as IsActive
                FROM auth.jwt_sessions 
                WHERE user_id = @userId 
                AND is_active = true 
                AND expires_at > CURRENT_TIMESTAMP
                ORDER BY last_accessed_at DESC";

            return await QueryAsync<JwtSession>(sql, new { userId });
        }

        public async Task<bool> RevokeAllUserSessionsAsync(Guid userId, string reason = "user_requested")
        {
            const string sql = @"
                UPDATE auth.jwt_sessions 
                SET is_active = false,
                    revoked_at = CURRENT_TIMESTAMP,
                    revoke_reason = @reason
                WHERE user_id = @userId 
                AND is_active = true";

            var rowsAffected = await ExecuteCommandAsync(sql, new { userId, reason });
            return rowsAffected > 0;
        }
    }
}