using Dapper;
using System;
using System.Threading.Tasks;
using System.Collections.Generic;
using AuthService.Domain.Entities;
using AuthService.Infrastructure.Data;

namespace AuthService.Infrastructure.Repositories
{
    public class DapperAuthRepository
    {
        private readonly DapperContext _context;

        public DapperAuthRepository(DapperContext context)
        {
            _context = context;
        }

        public async Task<dynamic> RegisterWithPassword(
            int userId,
            string email,
            string password,
            string role = "customer",
            string ipAddress = null,
            string userAgent = null,
            int? requestId = null)
        {
            using var connection = _context.CreateConnection();

            var parameters = new
            {
                p_user_id = userId,
                p_email = email,
                p_password = password,
                p_role_name = role,
                p_ip_address = ipAddress,
                p_user_agent = userAgent,
                p_request_id = requestId
            };

            var result = await connection.QueryFirstOrDefaultAsync<dynamic>(
                "SELECT * FROM auth.register_with_password(@p_user_id, @p_email, @p_password, @p_role_name, @p_ip_address::inet, @p_user_agent, @p_request_id)",
                parameters);

            return result;
        }

        public async Task<dynamic> AuthenticatePassword(
            string email,
            string password,
            string deviceInfo = "{}",
            int? requestId = null)
        {
            using var connection = _context.CreateConnection();

            var parameters = new
            {
                p_email = email,
                p_password = password,
                p_device_info = deviceInfo,
                p_request_id = requestId
            };

            var result = await connection.QueryFirstOrDefaultAsync<dynamic>(
                "SELECT * FROM auth.authenticate_password(@p_email, @p_password, @p_device_info::jsonb, @p_request_id)",
                parameters);

            return result;
        }

        public async Task<dynamic> VerifyEmail(string token, int? requestId = null)
        {
            using var connection = _context.CreateConnection();

            var parameters = new
            {
                p_token = token,
                p_request_id = requestId
            };

            var result = await connection.QueryFirstOrDefaultAsync<dynamic>(
                "SELECT * FROM auth.verify_email(@p_token, @p_request_id)",
                parameters);

            return result;
        }

        public async Task<dynamic> RefreshJwtToken(
            string refreshJti,
            string deviceInfo = "{}",
            int? requestId = null)
        {
            using var connection = _context.CreateConnection();

            var parameters = new
            {
                p_refresh_jti = refreshJti,
                p_device_info = deviceInfo,
                p_request_id = requestId
            };

            var result = await connection.QueryFirstOrDefaultAsync<dynamic>(
                "SELECT * FROM auth.refresh_jwt_token(@p_refresh_jti, @p_device_info::jsonb, @p_request_id)",
                parameters);

            return result;
        }

        public async Task<dynamic> LogoutSession(
            string jti,
            string reason = "user_logout",
            int? requestId = null)
        {
            using var connection = _context.CreateConnection();

            var parameters = new
            {
                p_jti = jti,
                p_reason = reason,
                p_request_id = requestId
            };

            var result = await connection.QueryFirstOrDefaultAsync<dynamic>(
                "SELECT * FROM auth.logout_session(@p_jti, @p_reason, @p_request_id)",
                parameters);

            return result;
        }

        public async Task<int> GetActiveSessionsCount(int userId)
        {
            using var connection = _context.CreateConnection();

            var result = await connection.ExecuteScalarAsync<int>(
                "SELECT auth.get_active_sessions_count(@p_user_id)",
                new { p_user_id = userId });

            return result;
        }

        public async Task<int> CleanupExpiredTokens()
        {
            using var connection = _context.CreateConnection();

            var result = await connection.ExecuteScalarAsync<int>(
                "SELECT auth.cleanup_expired_tokens()");

            return result;
        }

        // Additional helper methods
        public async Task<bool> ValidatePassword(string password)
        {
            using var connection = _context.CreateConnection();

            var result = await connection.QueryFirstOrDefaultAsync<dynamic>(
                "SELECT * FROM auth.validate_password_strength(@p_password)",
                new { p_password = password });

            return (result.valid as bool?) ?? false;
        }

        public async Task<bool> ValidateEmail(string email)
        {
            using var connection = _context.CreateConnection();

            var result = await connection.ExecuteScalarAsync<bool>(
                "SELECT auth.validate_email(@p_email)",
                new { p_email = email });

            return result;
        }
    }
}