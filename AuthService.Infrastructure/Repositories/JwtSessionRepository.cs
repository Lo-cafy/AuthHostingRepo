using Dapper;
using AuthService.Domain.Entities;
using AuthService.Infrastructure.Data.Interfaces;
using AuthService.Infrastructure.Interfaces;

namespace AuthService.Infrastructure.Repositories
{
    public class JwtSessionRepository : IJwtSessionRepository
    {
        private readonly IDbConnectionFactory _connectionFactory;

        public JwtSessionRepository(IDbConnectionFactory connectionFactory)
        {
            _connectionFactory = connectionFactory;
        }

        public async Task<JwtSession?> GetByJtiAsync(string jti)
        {
            using var connection = await _connectionFactory.CreateConnectionAsync();

            var sql = @"
                SELECT 
                    session_id AS SessionId,
                    user_id AS UserId,
                    jti AS Jti,
                    refresh_jti AS RefreshJti,
                    ip_address AS IpAddress,
                    user_agent AS UserAgent,
                    location AS Location,
                    created_at AS CreatedAt,
                    last_accessed_at AS LastAccessedAt,
                    expires_at AS ExpiresAt,
                    status = 'active' AS IsActive,
                    revoked_at AS RevokedAt,
                    revoke_reason AS RevokeReason
                FROM auth.jwt_sessions
                WHERE jti = @Jti";

            return await connection.QueryFirstOrDefaultAsync<JwtSession>(sql, new { Jti = jti });
        }

        public async Task<IEnumerable<JwtSession>> GetActiveSessionsByUserIdAsync(int userId)
        {
            using var connection = await _connectionFactory.CreateConnectionAsync();

            var sql = @"
                SELECT 
                    session_id AS SessionId,
                    user_id AS UserId,
                    jti AS Jti,
                    refresh_jti AS RefreshJti,
                    ip_address AS IpAddress,
                    user_agent AS UserAgent,
                    location AS Location,
                    created_at AS CreatedAt,
                    last_accessed_at AS LastAccessedAt,
                    expires_at AS ExpiresAt,
                    status = 'active' AS IsActive,
                    revoked_at AS RevokedAt,
                    revoke_reason AS RevokeReason
                FROM auth.jwt_sessions
                WHERE user_id = @UserId AND status = 'active'";

            return await connection.QueryAsync<JwtSession>(sql, new { UserId = userId });
        }

        public async Task<JwtSession> CreateAsync(JwtSession session)
        {
            using var connection = await _connectionFactory.CreateConnectionAsync();

            var sql = @"
                INSERT INTO auth.jwt_sessions (
                    user_id, jti, refresh_jti, ip_address, user_agent, 
                    location, expires_at, status
                ) VALUES (
                    @UserId, @Jti, @RefreshJti, @IpAddress, @UserAgent,
                    @Location::jsonb, @ExpiresAt, 'active'
                ) RETURNING session_id";

            session.SessionId = await connection.ExecuteScalarAsync<int>(sql, session);
            return session;
        }
        public async Task<JwtSession> GetByRefreshJtiAsync(string refreshJti)
        {
            using var connection = await _connectionFactory.CreateConnectionAsync();

            var sql = @"
            SELECT 
                session_id AS SessionId,
                user_id AS UserId,
                jti AS Jti,
                refresh_jti AS RefreshJti,
                ip_address AS IpAddress,
                user_agent AS UserAgent,
                location AS Location,
                created_at AS CreatedAt,
                last_accessed_at AS LastAccessedAt,
                expires_at AS ExpiresAt,
                status = 'active' AS IsActive,
                revoked_at AS RevokedAt,
                revoke_reason AS RevokeReason
            FROM auth.jwt_sessions
            WHERE refresh_jti = @RefreshJti";

            return await connection.QueryFirstOrDefaultAsync<JwtSession>(
                sql,
                new { RefreshJti = refreshJti }
            );
        }

        public async Task UpdateAsync(JwtSession session)
        {
            using var connection = await _connectionFactory.CreateConnectionAsync();

            var sql = @"
            UPDATE auth.jwt_sessions 
            SET 
                last_accessed_at = @LastAccessedAt,
                status = CASE 
                    WHEN @IsActive = false THEN 'revoked'
                    ELSE status 
                END,
                revoked_at = CASE 
                    WHEN @IsActive = false THEN CURRENT_TIMESTAMP
                    ELSE revoked_at 
                END,
                revoke_reason = CASE 
                    WHEN @IsActive = false THEN @RevokeReason
                    ELSE revoke_reason 
                END
            WHERE session_id = @SessionId";

            await connection.ExecuteAsync(sql, session);
        }

    }
}