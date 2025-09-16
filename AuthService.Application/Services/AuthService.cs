using AuthService.Application.DTOs.Auth;
using AuthService.Application.DTOs.Common;
using AuthService.Application.Interfaces;
using AuthService.Domain.Entities;
using AuthService.Infrastructure.Data.Interfaces;
using AuthService.Infrastructure.Interfaces;
using AuthService.Infrastructure.Repositories;
using AuthService.Shared.Exceptions;
using Microsoft.Extensions.Logging;
using Newtonsoft.Json;
using Newtonsoft.Json;
using Npgsql;
using NpgsqlTypes;
using System;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace AuthService.Application.Services
{
    public class AuthService : IAuthService
    {
        private readonly IDbConnectionFactory _connectionFactory;
        private readonly ILogger<AuthService> _logger;

        public AuthService(IDbConnectionFactory connectionFactory, ILogger<AuthService> logger)
        {
            _connectionFactory = connectionFactory;
            _logger = logger;
        }

        public async Task<RegisterResponseDto> RegisterAsync(RegisterRequestDto request)
        {
            // Input validation (as before)
            if (string.IsNullOrEmpty(request.Email) || string.IsNullOrEmpty(request.Password))
                return new RegisterResponseDto { Success = false, Message = "Email and password are required" };

            if (request.Password != request.ConfirmPassword)
                return new RegisterResponseDto { Success = false, Message = "Passwords do not match" };

            try
            {
                using var connection = _connectionFactory.CreateConnection();
                await connection.OpenAsync();

                using var command = new NpgsqlCommand("SELECT auth.register_with_password(@p_user_id, @p_email, @p_password, @p_role_name, @p_ip_address, @p_user_agent, @p_request_id)", connection);

                command.Parameters.Add(new NpgsqlParameter("@p_user_id", NpgsqlDbType.Uuid) { Value = Guid.NewGuid() });
                command.Parameters.Add(new NpgsqlParameter("@p_email", NpgsqlDbType.Varchar, 100) { Value = request.Email.ToLower() });
                command.Parameters.Add(new NpgsqlParameter("@p_password", NpgsqlDbType.Text) { Value = request.Password });
                command.Parameters.Add(new NpgsqlParameter("@p_role_name", NpgsqlDbType.Varchar, 50) { Value = request.Role ?? "customer" });
                command.Parameters.Add(new NpgsqlParameter("@p_ip_address", NpgsqlDbType.Inet) { Value = request.DeviceInfo?.IpAddress ?? "127.0.0.1" });
                command.Parameters.Add(new NpgsqlParameter("@p_user_agent", NpgsqlDbType.Text) { Value = request.DeviceInfo?.UserAgent ?? "Unknown" });
                command.Parameters.Add(new NpgsqlParameter("@p_request_id", NpgsqlDbType.Uuid) { Value = Guid.NewGuid() });

                var result = await command.ExecuteScalarAsync();
                var jsonResult = result?.ToString();

                if (string.IsNullOrEmpty(jsonResult))
                    return new RegisterResponseDto { Success = false, Message = "No response from database" };

                var spResponse = JsonConvert.DeserializeObject<dynamic>(jsonResult);

                if (!(bool)spResponse.success)
                    return new RegisterResponseDto { Success = false, Message = spResponse.message.ToString() ?? "Registration failed", ErrorCode = spResponse.error.ToString() };

                return new RegisterResponseDto
                {
                    Success = true,
                    UserId = spResponse.user_id,
                    Email = request.Email,
                    VerificationToken = spResponse.verification_token,
                    Message = spResponse.message
                };
            }
            catch (NpgsqlException nex)
            {
                _logger.LogError(nex, "Database error during registration for email: {Email}", request.Email);
                return new RegisterResponseDto { Success = false, Message = $"Database error: {nex.Message}" };
            }
            catch (JsonException jex)
            {
                _logger.LogError(jex, "JSON parsing error during registration");
                return new RegisterResponseDto { Success = false, Message = "Invalid response from database" };
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Registration failed for email: {Email}", request.Email);
                return new RegisterResponseDto { Success = false, Message = "An unexpected error occurred" };
            }
        }


        public async Task<LoginResponseDto> LoginAsync(LoginRequestDto request)
        {
            try
            {
                using var connection = _connectionFactory.CreateConnection();
                await connection.OpenAsync();

                var deviceInfo = JsonConvert.SerializeObject(new
                {
                    ip_address = request.DeviceInfo?.IpAddress ?? "127.0.0.1",
                    user_agent = request.DeviceInfo?.UserAgent ?? "Unknown",
                    device_id = request.DeviceInfo?.DeviceId,
                    device_name = request.DeviceInfo?.DeviceName,
                    device_type = request.DeviceInfo?.DeviceType,
                    location = request.DeviceInfo?.Location
                });

                using var command = new NpgsqlCommand("SELECT auth.authenticate_password(@p_email, @p_password, @p_device_info, @p_request_id)", (NpgsqlConnection?)connection);
                command.Parameters.AddWithValue("@p_email", request.Email.ToLower());
                command.Parameters.AddWithValue("@p_password", request.Password);
                command.Parameters.AddWithValue("@p_device_info", NpgsqlTypes.NpgsqlDbType.Jsonb, deviceInfo);
                command.Parameters.AddWithValue("@p_request_id", Guid.NewGuid());

                var result = await command.ExecuteScalarAsync();
                var jsonResult = result?.ToString();

                if (!string.IsNullOrEmpty(jsonResult))
                {
                    var spResponse = JsonConvert.DeserializeObject<dynamic>(jsonResult);

                    if (!(bool)spResponse.success)
                    {
                        throw new AuthException(spResponse.message.ToString());
                    }

                    return new LoginResponseDto
                    {
                        AccessToken = spResponse.tokens.access_token_jti,
                        RefreshToken = spResponse.tokens.refresh_token_jti,
                        ExpiresIn = spResponse.tokens.expires_in ?? 3600,
                        UserId = spResponse.user_id,
                        Email = spResponse.email,
                        Roles = spResponse.roles?.ToObject<string[]>() ?? new[] { "customer" }
                    };
                }

                throw new AuthException("Authentication failed");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Login failed for email: {Email}", request.Email);
                throw;
            }
        }

        public async Task<AuthResultDto> AuthenticateAsync(string email, string password)
        {
           
            try
            {
                using var connection = _connectionFactory.CreateConnection();
                await connection.OpenAsync();

                using var command = new NpgsqlCommand("SELECT auth.authenticate_password(@p_email, @p_password, '{}'::jsonb, @p_request_id)", connection);
                command.Parameters.AddWithValue("@p_email", email.ToLower());
                command.Parameters.AddWithValue("@p_password", password);
                command.Parameters.AddWithValue("@p_request_id", Guid.NewGuid());

                var result = await command.ExecuteScalarAsync();
                var jsonResult = result?.ToString();

                if (!string.IsNullOrEmpty(jsonResult))
                {
                    var spResponse = JsonConvert.DeserializeObject<dynamic>(jsonResult);

                    if (!(bool)spResponse.success)
                        throw new AuthException(spResponse.message.ToString());

                    return new AuthResultDto
                    {
                        Success = true,
                        AccessToken = spResponse.tokens.access_token_jti,
                        RefreshToken = spResponse.tokens.refresh_token_jti,
                        ExpiresIn = spResponse.tokens.expires_in ?? 3600,
                        UserId = spResponse.user_id,
                        Email = spResponse.email,
                        Roles = spResponse.roles?.ToObject<string[]>() ?? new[] { "customer" }
                    };
                }

                throw new AuthException("Authentication failed.");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Authentication failed for email: {Email}", email);
                throw;
            }
        }

        public async Task<RefreshTokenResponseDto> RefreshTokenAsync(RefreshTokenRequestDto request)
        {
            try
            {
                using var connection = _connectionFactory.CreateConnection();
                await connection.OpenAsync();

                var deviceInfo = JsonConvert.SerializeObject(new
                {
                    ip_address = request.IpAddress ?? "127.0.0.1",
                    user_agent = request.UserAgent ?? "Unknown"
                });

                using var command = new NpgsqlCommand("SELECT auth.refresh_jwt_token(@p_refresh_jti, @p_device_info, @p_request_id)", connection);
                command.Parameters.AddWithValue("@p_refresh_jti", request.RefreshToken);
                command.Parameters.AddWithValue("@p_device_info", NpgsqlTypes.NpgsqlDbType.Jsonb, deviceInfo);
                command.Parameters.AddWithValue("@p_request_id", Guid.NewGuid());

                var result = await command.ExecuteScalarAsync();
                var jsonResult = result?.ToString();

                if (!string.IsNullOrEmpty(jsonResult))
                {
                    var spResponse = JsonConvert.DeserializeObject<dynamic>(jsonResult);

                    if (!(bool)spResponse.success)
                    {
                        throw new AuthException(spResponse.message.ToString());
                    }

                    return new RefreshTokenResponseDto
                    {
                        AccessToken = spResponse.tokens.access_token_jti,
                        ExpiresIn = spResponse.tokens.expires_in ?? 3600
                    };
                }

                throw new AuthException("Token refresh failed");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Token refresh failed");
                throw;
            }
        }

        public async Task<bool> ValidateTokenAsync(string token)
        {
            try
            {
                using var connection = _connectionFactory.CreateConnection();
                await connection.OpenAsync();

                using var command = new NpgsqlCommand("SELECT auth.validate_session(@p_jti)", connection);
                command.Parameters.AddWithValue("@p_jti", token);

                var result = await command.ExecuteScalarAsync();
                return result != null && (bool)result;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Token validation failed");
                return false;
            }
        }

        public async Task LogoutAsync(string jti)
        {
            try
            {
                using var connection = _connectionFactory.CreateConnection();
                await connection.OpenAsync();

                using var command = new NpgsqlCommand("SELECT auth.logout_session(@p_jti, @p_reason, @p_request_id)", connection);
                command.Parameters.AddWithValue("@p_jti", jti);
                command.Parameters.AddWithValue("@p_reason", "user_logout");
                command.Parameters.AddWithValue("@p_request_id", Guid.NewGuid());

                await command.ExecuteScalarAsync();
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Logout failed for JTI: {Jti}", jti);
                throw;
            }
        }
    }

}