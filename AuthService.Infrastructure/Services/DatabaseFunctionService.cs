using System;
using System.Text.Json;
using System.Threading.Tasks;
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

        private async Task<NpgsqlConnection> GetConnectionAsync()
        {
            var connection = (NpgsqlConnection)await _connectionFactory.CreateConnectionAsync();

             
            using var schemaCommand = new NpgsqlCommand("SET search_path = auth, public;", connection);
            await schemaCommand.ExecuteNonQueryAsync();

            return connection;
        }

        public async Task<JsonDocument> RegisterWithPasswordAsync(
            int userId,
            string email,
            string password,
            string role = "customer",
            string ipAddress = null,
            string userAgent = null,
            Guid? requestId = null)  
        {
            try
            {
                using var connection = await GetConnectionAsync();
                using var command = new NpgsqlCommand(
                    "SELECT auth.register_user_enhanced(@p_email, @p_password, @p_role_name, @p_device_info::jsonb, @p_request_id)",
                    connection);

                command.Parameters.Add(new NpgsqlParameter("@p_email", NpgsqlDbType.Varchar) { Value = email.ToLower() });
                command.Parameters.Add(new NpgsqlParameter("@p_password", NpgsqlDbType.Varchar) { Value = password });
                command.Parameters.Add(new NpgsqlParameter("@p_role_name", NpgsqlDbType.Varchar) { Value = role });

                var deviceInfo = new
                {
                    ip_address = !string.IsNullOrEmpty(ipAddress) ? ipAddress : "127.0.0.1",
                    user_agent = userAgent ?? "Unknown"
                };
                command.Parameters.Add(new NpgsqlParameter("@p_device_info", NpgsqlDbType.Jsonb) { Value = JsonSerializer.Serialize(deviceInfo) });

                // CORRECTED logic
                command.Parameters.Add(new NpgsqlParameter("@p_request_id", NpgsqlDbType.Varchar)
                {
                    Value = requestId?.ToString() ?? (object)DBNull.Value
                });


                var result = await command.ExecuteScalarAsync();
                var jsonResult = result?.ToString();

                if (string.IsNullOrEmpty(jsonResult))
                {
                    throw new InvalidOperationException("No result from registration procedure");
                }

                return JsonDocument.Parse(jsonResult);
            }
            catch (PostgresException pgEx)
            {
                _logger.LogError(pgEx, "PostgreSQL error during registration for email {Email}. Code: {Code}, Message: {Message}", email, pgEx.SqlState, pgEx.Message);
                var errorResponse = new { success = false, error = "DB_ERROR", message = "Registration failed due to database error", code = 500, details = new { sqlState = pgEx.SqlState, severity = pgEx.Severity, hint = pgEx.Hint } };
                return JsonDocument.Parse(JsonSerializer.Serialize(errorResponse));
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Registration failed for email {Email}", email);
                var errorResponse = new { success = false, error = "INTERNAL_ERROR", message = "Registration failed due to an internal error", code = 500 };
                return JsonDocument.Parse(JsonSerializer.Serialize(errorResponse));
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
                using var connection = await GetConnectionAsync();
                using var command = new NpgsqlCommand(
                    "SELECT auth.authenticate_user_enhanced(" +
                        "p_email := @p_email, " +
                        "p_password := @p_password, " +
                        "p_device_info := @p_device_info, " +
                        "p_request_id := @p_request_id)",
                    connection);

                command.Parameters.Add(new NpgsqlParameter("@p_email", NpgsqlDbType.Varchar) { Value = email.ToLower() });
                command.Parameters.Add(new NpgsqlParameter("@p_password", NpgsqlDbType.Text) { Value = password });
                var deviceInfoJson = deviceInfo != null ? JsonSerializer.Serialize(deviceInfo) : "{}";
                command.Parameters.Add(new NpgsqlParameter("@p_device_info", NpgsqlDbType.Jsonb) { Value = deviceInfoJson });
                command.Parameters.Add(new NpgsqlParameter("@p_request_id", NpgsqlDbType.Varchar) { Value = requestId.HasValue ? (object)requestId.Value.ToString() : DBNull.Value });

                var result = await command.ExecuteScalarAsync();
                var jsonResult = result?.ToString();

                if (string.IsNullOrEmpty(jsonResult))
                {
                    _logger.LogWarning("No result returned from authenticate_user_enhanced for email: {Email}", email);
                    return JsonDocument.Parse(@"{ ""success"": false, ""error"": ""NO_RESULT"", ""message"": ""Authentication failed"", ""code"": 500 }");
                }
                return JsonDocument.Parse(jsonResult);
            }
            catch (PostgresException pgEx)
            {
                _logger.LogError(pgEx, "PostgreSQL error during authentication for email {Email}. Code: {Code}, Message: {Message}", email, pgEx.SqlState, pgEx.Message);
                var errorResponse = new { success = false, error = "DB_ERROR", message = "Authentication failed due to database error", code = 500, details = new { sqlState = pgEx.SqlState, severity = pgEx.Severity, hint = pgEx.Hint } };
                return JsonDocument.Parse(JsonSerializer.Serialize(errorResponse));
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Unexpected error during authentication for email {Email}", email);
                return JsonDocument.Parse(@"{ ""success"": false, ""error"": ""INTERNAL_ERROR"", ""message"": ""An unexpected error occurred during authentication"", ""code"": 500 }");
            }
        }

        public async Task<JsonDocument> RefreshJwtTokenAsync(
            string refreshJti,
            object deviceInfo = null,
            Guid? requestId = null)  
        {
            try
            {
                using var connection = await GetConnectionAsync();
                using var command = new NpgsqlCommand(
                    "SELECT auth.refresh_jwt_token(@p_refresh_jti, @p_device_info::jsonb, @p_request_id)",
                    connection);

                command.Parameters.Add(new NpgsqlParameter("@p_refresh_jti", NpgsqlDbType.Varchar) { Value = refreshJti });

                var deviceInfoJson = deviceInfo != null ? JsonSerializer.Serialize(deviceInfo) : "{}";
                command.Parameters.Add(new NpgsqlParameter("@p_device_info", NpgsqlDbType.Jsonb) { Value = deviceInfoJson });

               
                command.Parameters.Add(new NpgsqlParameter("@p_request_id", NpgsqlDbType.Varchar) { Value = requestId?.ToString() ?? (object)DBNull.Value });

                var result = await command.ExecuteScalarAsync();
                var jsonResult = result?.ToString();

                if (string.IsNullOrEmpty(jsonResult))
                {
                    return JsonDocument.Parse(@"{ ""success"": false, ""error"": ""NO_RESULT"", ""message"": ""Token refresh failed"", ""code"": 500 }");
                }

                return JsonDocument.Parse(jsonResult);
            }
            catch (PostgresException pgEx)
            {
                _logger.LogError(pgEx, "PostgreSQL error during token refresh. Code: {Code}, Message: {Message}", pgEx.SqlState, pgEx.Message);
                var errorResponse = new { success = false, error = "DB_ERROR", message = "Token refresh failed due to database error", code = 500, details = new { sqlState = pgEx.SqlState, severity = pgEx.Severity, hint = pgEx.Hint } };
                return JsonDocument.Parse(JsonSerializer.Serialize(errorResponse));
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Token refresh failed");
                return JsonDocument.Parse(@"{ ""success"": false, ""error"": ""INTERNAL_ERROR"", ""message"": ""An unexpected error occurred during token refresh"", ""code"": 500 }");
            }
        }

        public async Task<JsonDocument> LogoutSessionAsync(
            string jti,
            string reason = "user_logout",
            Guid? requestId = null)  
        {
            try
            {
                using var connection = await GetConnectionAsync();
                using var command = new NpgsqlCommand(
                    "SELECT auth.logout_session(@p_jti, @p_reason, @p_request_id)",
                    connection);

                command.Parameters.Add(new NpgsqlParameter("@p_jti", NpgsqlDbType.Varchar) { Value = jti });
                command.Parameters.Add(new NpgsqlParameter("@p_reason", NpgsqlDbType.Varchar) { Value = reason });

            
                command.Parameters.Add(new NpgsqlParameter("@p_request_id", NpgsqlDbType.Varchar) { Value = requestId?.ToString() ?? (object)DBNull.Value });

                var result = await command.ExecuteScalarAsync();
                var jsonResult = result?.ToString();

                if (string.IsNullOrEmpty(jsonResult))
                {
                    return JsonDocument.Parse(@"{ ""success"": false, ""error"": ""NO_RESULT"", ""message"": ""Logout failed"", ""code"": 500 }");
                }

                return JsonDocument.Parse(jsonResult);
            }
            catch (PostgresException pgEx)
            {
                _logger.LogError(pgEx, "PostgreSQL error during logout. Code: {Code}, Message: {Message}", pgEx.SqlState, pgEx.Message);
                var errorResponse = new { success = false, error = "DB_ERROR", message = "Logout failed due to database error", code = 500, details = new { sqlState = pgEx.SqlState, severity = pgEx.Severity, hint = pgEx.Hint } };
                return JsonDocument.Parse(JsonSerializer.Serialize(errorResponse));
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Logout failed for JTI: {Jti}", jti);
                return JsonDocument.Parse(@"{ ""success"": false, ""error"": ""INTERNAL_ERROR"", ""message"": ""An unexpected error occurred during logout"", ""code"": 500 }");
            }
        }
    }
}