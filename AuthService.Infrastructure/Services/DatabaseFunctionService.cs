using System.Text.Json;
using Npgsql;
using NpgsqlTypes;
using AuthService.Infrastructure.Interfaces;
using Microsoft.Extensions.Logging;
using AuthService.Infrastructure.Data.Interfaces;

namespace AuthService.Infrastructure.Services
{
    public class DatabaseFunctionService : IDatabaseFunctionService
    {
        private readonly IDbConnectionFactory _connectionFactory;
        private readonly ILogger<DatabaseFunctionService> _logger;

        public DatabaseFunctionService(
            IDbConnectionFactory connectionFactory,
            ILogger<DatabaseFunctionService> logger)
        {
            _connectionFactory = connectionFactory;
            _logger = logger;
        }

        public async Task<JsonDocument> RegisterWithPasswordAsync(
            Guid userId,
            string email,
            string password,
            string role = "customer",
            string ipAddress = null,
            string userAgent = null,
            Guid? requestId = null)
        {
            try
            {
                // Cast to NpgsqlConnection since we know it's the concrete type
                using var connection = (NpgsqlConnection)_connectionFactory.CreateConnection();
                await connection.OpenAsync();

                using var command = new NpgsqlCommand(
                    "SELECT auth.register_with_password(@p_user_id, @p_email, @p_password, @p_role_name, @p_ip_address::inet, @p_user_agent, @p_request_id)",
                    connection);

                command.Parameters.AddWithValue("@p_user_id", userId);
                command.Parameters.AddWithValue("@p_email", email.ToLower());
                command.Parameters.AddWithValue("@p_password", password);
                command.Parameters.AddWithValue("@p_role_name", role);
                command.Parameters.AddWithValue("@p_ip_address", NpgsqlDbType.Inet, ipAddress ?? "127.0.0.1");
                command.Parameters.AddWithValue("@p_user_agent", userAgent ?? "Unknown");
                command.Parameters.AddWithValue("@p_request_id", requestId ?? Guid.NewGuid());

                var result = await command.ExecuteScalarAsync();
                var jsonResult = result?.ToString();

                if (string.IsNullOrEmpty(jsonResult))
                {
                    throw new InvalidOperationException("No result from stored procedure");
                }

                return JsonDocument.Parse(jsonResult);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Database function register_with_password failed");
                throw;
            }
        }

        public async Task<JsonDocument> AuthenticatePasswordAsync(
            string email,
            string password,
            object deviceInfo = null,
            Guid? requestId = null)
        {
            try
            {
                using var connection = (NpgsqlConnection)_connectionFactory.CreateConnection();
                await connection.OpenAsync();

                using var command = new NpgsqlCommand(
                    "SELECT auth.authenticate_password(@p_email, @p_password, @p_device_info::jsonb, @p_request_id)",
                    connection);

                command.Parameters.AddWithValue("@p_email", email.ToLower());
                command.Parameters.AddWithValue("@p_password", password);

                var deviceInfoJson = deviceInfo != null
                    ? JsonSerializer.Serialize(deviceInfo)
                    : "{}";
                command.Parameters.AddWithValue("@p_device_info", NpgsqlDbType.Jsonb, deviceInfoJson);
                command.Parameters.AddWithValue("@p_request_id", requestId ?? Guid.NewGuid());

                var result = await command.ExecuteScalarAsync();
                var jsonResult = result?.ToString();

                if (string.IsNullOrEmpty(jsonResult))
                {
                    throw new InvalidOperationException("No result from stored procedure");
                }

                return JsonDocument.Parse(jsonResult);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Database function authenticate_password failed");
                throw;
            }
        }

        public async Task<JsonDocument> VerifyEmailAsync(
            string token,
            Guid? requestId = null)
        {
            try
            {
                using var connection = (NpgsqlConnection)_connectionFactory.CreateConnection();
                await connection.OpenAsync();

                using var command = new NpgsqlCommand(
                    "SELECT auth.verify_email(@p_token, @p_request_id)",
                    connection);

                command.Parameters.AddWithValue("@p_token", token);
                command.Parameters.AddWithValue("@p_request_id", requestId ?? Guid.NewGuid());

                var result = await command.ExecuteScalarAsync();
                var jsonResult = result?.ToString();

                if (string.IsNullOrEmpty(jsonResult))
                {
                    throw new InvalidOperationException("No result from stored procedure");
                }

                return JsonDocument.Parse(jsonResult);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Database function verify_email failed");
                throw;
            }
        }

        public async Task<JsonDocument> RefreshJwtTokenAsync(
            string refreshJti,
            object deviceInfo = null,
            Guid? requestId = null)
        {
            try
            {
                using var connection = (NpgsqlConnection)_connectionFactory.CreateConnection();
                await connection.OpenAsync();

                using var command = new NpgsqlCommand(
                    "SELECT auth.refresh_jwt_token(@p_refresh_jti, @p_device_info::jsonb, @p_request_id)",
                    connection);

                command.Parameters.AddWithValue("@p_refresh_jti", refreshJti);

                var deviceInfoJson = deviceInfo != null
                    ? JsonSerializer.Serialize(deviceInfo)
                    : "{}";
                command.Parameters.AddWithValue("@p_device_info", NpgsqlDbType.Jsonb, deviceInfoJson);
                command.Parameters.AddWithValue("@p_request_id", requestId ?? Guid.NewGuid());

                var result = await command.ExecuteScalarAsync();
                var jsonResult = result?.ToString();

                if (string.IsNullOrEmpty(jsonResult))
                {
                    throw new InvalidOperationException("No result from stored procedure");
                }

                return JsonDocument.Parse(jsonResult);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Database function refresh_jwt_token failed");
                throw;
            }
        }

        public async Task<JsonDocument> LogoutSessionAsync(
            string jti,
            string reason = "user_logout",
            Guid? requestId = null)
        {
            try
            {
                using var connection = (NpgsqlConnection)_connectionFactory.CreateConnection();
                await connection.OpenAsync();

                using var command = new NpgsqlCommand(
                    "SELECT auth.logout_session(@p_jti, @p_reason, @p_request_id)",
                    connection);

                command.Parameters.AddWithValue("@p_jti", jti);
                command.Parameters.AddWithValue("@p_reason", reason);
                command.Parameters.AddWithValue("@p_request_id", requestId ?? Guid.NewGuid());

                var result = await command.ExecuteScalarAsync();
                var jsonResult = result?.ToString();

                if (string.IsNullOrEmpty(jsonResult))
                {
                    throw new InvalidOperationException("No result from stored procedure");
                }

                return JsonDocument.Parse(jsonResult);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Database function logout_session failed");
                throw;
            }
        }
    }
}