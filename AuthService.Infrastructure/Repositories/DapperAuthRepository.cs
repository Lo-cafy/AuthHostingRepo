using Dapper;
using System;
using System.Threading.Tasks;
using System.Collections.Generic;
using AuthService.Domain.Entities;
using AuthService.Infrastructure.Data.Interfaces;
using Newtonsoft.Json;

namespace AuthService.Infrastructure.Repositories
{
    public class DapperAuthRepository : BaseRepository
    {
        public DapperAuthRepository(IDbConnectionFactory connectionFactory)
            : base(connectionFactory)
        {
        }

        public async Task<dynamic> RegisterWithPassword(
            Guid userId,
            string email,
            string password,
            string role = "customer",
            string ipAddress = null,
            string userAgent = null,
            Guid? requestId = null)
        {
            var parameters = new DynamicParameters();
            parameters.Add("p_user_id", userId);
            parameters.Add("p_email", email);
            parameters.Add("p_password", password);
            parameters.Add("p_role_name", role);
            parameters.Add("p_ip_address", ipAddress);
            parameters.Add("p_user_agent", userAgent);
            parameters.Add("p_request_id", requestId);

            var jsonResult = await ExecuteAsync<string>(
                "SELECT auth.register_with_password(@p_user_id, @p_email, @p_password, @p_role_name, @p_ip_address::inet, @p_user_agent, @p_request_id)",
                parameters);

            return JsonConvert.DeserializeObject<dynamic>(jsonResult);
        }

        public async Task<dynamic> AuthenticatePassword(
            string email,
            string password,
            object deviceInfo = null,
            Guid? requestId = null)
        {
            var parameters = new DynamicParameters();
            parameters.Add("p_email", email);
            parameters.Add("p_password", password);
            parameters.Add("p_device_info", JsonConvert.SerializeObject(deviceInfo ?? new { }));
            parameters.Add("p_request_id", requestId);

            var jsonResult = await ExecuteAsync<string>(
                "SELECT auth.authenticate_password(@p_email, @p_password, @p_device_info::jsonb, @p_request_id)",
                parameters);

            return JsonConvert.DeserializeObject<dynamic>(jsonResult);
        }

        public async Task<dynamic> VerifyEmail(string token, Guid? requestId = null)
        {
            var parameters = new DynamicParameters();
            parameters.Add("p_token", token);
            parameters.Add("p_request_id", requestId);

            var jsonResult = await ExecuteAsync<string>(
                "SELECT auth.verify_email(@p_token, @p_request_id)",
                parameters);

            return JsonConvert.DeserializeObject<dynamic>(jsonResult);
        }

        public async Task<dynamic> RefreshJwtToken(
            string refreshJti,
            object deviceInfo = null,
            Guid? requestId = null)
        {
            var parameters = new DynamicParameters();
            parameters.Add("p_refresh_jti", refreshJti);
            parameters.Add("p_device_info", JsonConvert.SerializeObject(deviceInfo ?? new { }));
            parameters.Add("p_request_id", requestId);

            var jsonResult = await ExecuteAsync<string>(
                "SELECT auth.refresh_jwt_token(@p_refresh_jti, @p_device_info::jsonb, @p_request_id)",
                parameters);

            return JsonConvert.DeserializeObject<dynamic>(jsonResult);
        }

        public async Task<dynamic> LogoutSession(
            string jti,
            string reason = "user_logout",
            Guid? requestId = null)
        {
            var parameters = new DynamicParameters();
            parameters.Add("p_jti", jti);
            parameters.Add("p_reason", reason);
            parameters.Add("p_request_id", requestId);

            var jsonResult = await ExecuteAsync<string>(
                "SELECT auth.logout_session(@p_jti, @p_reason, @p_request_id)",
                parameters);

            return JsonConvert.DeserializeObject<dynamic>(jsonResult);
        }

        public async Task<int> GetActiveSessionsCount(Guid userId)
        {
            return await ExecuteScalarAsync<int>(
                "SELECT auth.get_active_sessions_count(@p_user_id)",
                new { p_user_id = userId });
        }

        public async Task<int> CleanupExpiredTokens()
        {
            return await ExecuteScalarAsync<int>("SELECT auth.cleanup_expired_tokens()");
        }

        public async Task<dynamic> ValidatePasswordStrength(string password)
        {
            var jsonResult = await ExecuteAsync<string>(
                "SELECT auth.validate_password_strength(@p_password)",
                new { p_password = password });

            return JsonConvert.DeserializeObject<dynamic>(jsonResult);
        }

        public async Task<bool> ValidateEmail(string email)
        {
            return await ExecuteScalarAsync<bool>(
                "SELECT auth.validate_email(@p_email)",
                new { p_email = email });
        }

        public async Task<int> CalculateRiskScore(string ipAddress, string userAgent, Guid? userId = null)
        {
            var parameters = new DynamicParameters();
            parameters.Add("p_ip_address", ipAddress);
            parameters.Add("p_user_agent", userAgent);
            parameters.Add("p_user_id", userId);

            return await ExecuteScalarAsync<int>(
                "SELECT auth.calculate_risk_score(@p_ip_address::inet, @p_user_agent, @p_user_id)",
                parameters);
        }
    }
}