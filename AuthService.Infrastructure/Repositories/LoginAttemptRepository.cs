using System;
using System.Threading.Tasks;
using Dapper;
using AuthService.Domain.Entities;
using AuthService.Infrastructure.Data.Interfaces;
using AuthService.Infrastructure.Interfaces;

namespace AuthService.Infrastructure.Repositories
{
    public class LoginAttemptRepository : BaseRepository, ILoginAttemptRepository
    {
        public LoginAttemptRepository(IDbConnectionFactory connectionFactory)
            : base(connectionFactory)
        {
        }

        public async Task<int> GetRecentFailuresAsync(string fingerprint, int minutes)
        {
            const string sql = @"
                SELECT COUNT(*) 
                FROM auth.login_attempts 
                WHERE fingerprint = @fingerprint 
                AND attempted_at > CURRENT_TIMESTAMP - INTERVAL '{0} minutes'
                AND NOT success";

            var formattedSql = string.Format(sql, minutes);
            return await ExecuteScalarAsync<int>(formattedSql, new { fingerprint });
        }

        public async Task CreateAsync(LoginAttempt attempt)
        {
            const string sql = @"
                INSERT INTO auth.login_attempts (
                    attempt_id, user_id, identifier, auth_provider, success, 
                    failure_reason, ip_address, user_agent, country_code,
                    city, attempted_at, fingerprint
                ) VALUES (
                    @AttemptId, @UserId, @Identifier, @AuthProvider, @Success,
                    @FailureReason, @IpAddress::inet, @UserAgent, @CountryCode,
                    @City, @AttemptedAt, @Fingerprint
                )";

            attempt.AttemptId = new int();
            attempt.AttemptedAt = DateTime.UtcNow;

            await ExecuteCommandAsync(sql, attempt);
        }

        public async Task<int> GetFailedAttemptsCountAsync(int userId, int hours = 24)
        {
            const string sql = @"
                SELECT COUNT(*) 
                FROM auth.login_attempts 
                WHERE user_id = @userId 
                AND attempted_at > CURRENT_TIMESTAMP - INTERVAL '{0} hours'
                AND NOT success";

            var formattedSql = string.Format(sql, hours);
            return await ExecuteScalarAsync<int>(formattedSql, new { userId });
        }

        public async Task<bool> HasRecentSuccessfulLoginAsync(int userId, string ipAddress, int days = 7)
        {
            const string sql = @"
                SELECT EXISTS(
                    SELECT 1 FROM auth.login_attempts
                    WHERE user_id = @userId
                    AND ip_address = @ipAddress::inet
                    AND success = TRUE
                    AND attempted_at > CURRENT_TIMESTAMP - INTERVAL '{0} days'
                )";

            var formattedSql = string.Format(sql, days);
            return await ExecuteScalarAsync<bool>(formattedSql, new { userId, ipAddress });
        }
    }
}