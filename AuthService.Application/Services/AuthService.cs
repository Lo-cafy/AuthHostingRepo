using System;
using System.Linq;
using System.Text.Json;
using System.Threading.Tasks;
using System.Collections.Generic;
using Microsoft.Extensions.Logging;
using AuthService.Application.Interfaces;
using AuthService.Application.DTOs.Auth;
using AuthService.Application.DTOs.Common;
using AuthService.Infrastructure.Interfaces;
using AuthService.Domain.Entities;
using AuthService.Domain.Enums;
using AuthService.Shared.Exceptions;
using System.Security.Cryptography;
using System.Text;
using Newtonsoft.Json;

namespace AuthService.Application.Services
{
    public class AuthService : IAuthService
    {
        private readonly IDatabaseFunctionService _databaseFunctionService;
        private readonly IUserCredentialRepository _credentialRepository;
        private readonly IJwtService _jwtService;
        private readonly IPasswordService _passwordService;
        private readonly IJwtSessionRepository _sessionRepository;
        private readonly ILoginAttemptRepository _loginAttemptRepository;
        private readonly IDigitalFingerprintService _fingerprintService;
        private readonly ILogger<AuthService> _logger;

        public AuthService(
            IDatabaseFunctionService databaseFunctionService,
            IUserCredentialRepository credentialRepository,
            IJwtService jwtService,
            IPasswordService passwordService,
            IJwtSessionRepository sessionRepository,
            ILoginAttemptRepository loginAttemptRepository,
            IDigitalFingerprintService fingerprintService,
            ILogger<AuthService> logger)
        {
            _databaseFunctionService = databaseFunctionService;
            _credentialRepository = credentialRepository;
            _jwtService = jwtService;
            _passwordService = passwordService;
            _sessionRepository = sessionRepository;
            _loginAttemptRepository = loginAttemptRepository;
            _fingerprintService = fingerprintService;
            _logger = logger;
        }

        public async Task<LoginResponseDto> LoginAsync(LoginRequestDto request, DeviceInfoDto? deviceInfo = null)
        {
            try
            {
                deviceInfo ??= new DeviceInfoDto
                {
                    DeviceId = Guid.NewGuid().ToString(),
                    DeviceType = "Unknown",
                    IpAddress = "127.0.0.1",
                    UserAgent = "Unknown"
                };

                var requestId = Guid.NewGuid();

                // Create device info object for stored procedure
                var deviceInfoForSP = new
                {
                    ip_address = deviceInfo.IpAddress,
                    user_agent = deviceInfo.UserAgent,
                    device_id = deviceInfo.DeviceId,
                    device_name = deviceInfo.DeviceName,
                    device_type = deviceInfo.DeviceType,
                    location = deviceInfo.Location
                };

                var result = await _databaseFunctionService.AuthenticatePasswordAsync(
                    request.Email,
                    request.Password,
                    deviceInfoForSP,
                    requestId
                );

                using (result)
                {
                    var root = result.RootElement;

                    if (!root.GetProperty("success").GetBoolean())
                    {
                        var error = root.GetProperty("error").GetString();
                        var message = root.GetProperty("message").GetString();
                        var code = root.GetProperty("code").GetInt32();

                        if (code == 429)
                            throw new RateLimitException(message);
                        else if (code == 423)
                            throw new AuthException(message);
                        else if (code == 403 && error == "EMAIL_NOT_VERIFIED")
                        {
                            throw new AuthException("Please verify your email address before logging in");
                        }
                        else
                            throw new AuthException(message);
                    }

                    var userId = root.GetProperty("user_id").GetGuid();
                    var email = root.GetProperty("email").GetString();
                    var emailVerified = root.GetProperty("email_verified").GetBoolean();
                    var accountStatus = root.GetProperty("account_status").GetString();

                    var roles = root.GetProperty("roles").EnumerateArray()
                        .Select(r => r.GetString())
                        .ToList();

                    var tokens = root.GetProperty("tokens");
                    var accessJti = tokens.GetProperty("access_token_jti").GetString();
                    var refreshJti = tokens.GetProperty("refresh_token_jti").GetString();
                    var expiresIn = tokens.GetProperty("expires_in").GetInt32();

                    var session = root.GetProperty("session");
                    var sessionId = session.GetProperty("session_id").GetGuid();

                    // Generate actual JWT tokens
                    var roleEnum = Enum.Parse<RoleTypeEnum>(roles.FirstOrDefault() ?? "Customer", true);
                    var accessToken = _jwtService.GenerateAccessToken(userId, email, roleEnum, accessJti);
                    var refreshToken = _jwtService.GenerateRefreshToken(userId, refreshJti);

                    return new LoginResponseDto
                    {
                        Success = true,
                        AccessToken = accessToken,
                        RefreshToken = refreshToken,
                        ExpiresIn = expiresIn,
                        ExpiresAt = DateTime.UtcNow.AddSeconds(expiresIn),
                        User = new UserInfoDto
                        {
                            UserId = userId,
                            Email = email,
                            IsEmailVerified = emailVerified,
                            Role = roleEnum
                        },
                        Role = roleEnum
                    };
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Login failed for email: {Email}", request.Email);
                throw;
            }
        }

        public async Task<RegisterResponseDto> RegisterAsync(RegisterRequestDto request)
        {
            try
            {
                var userId = Guid.NewGuid();
                var requestId = Guid.NewGuid();

                var result = await _databaseFunctionService.RegisterWithPasswordAsync(
                    userId,
                    request.Email,
                    request.Password,
                    request.Role ?? "customer",
                    request.DeviceInfo?.IpAddress ?? "127.0.0.1",
                    request.DeviceInfo?.UserAgent ?? "Unknown",
                    requestId
                );

                using (result)
                {
                    var root = result.RootElement;

                    if (!root.GetProperty("success").GetBoolean())
                    {
                        var error = root.GetProperty("error").GetString();
                        var message = root.GetProperty("message").GetString();
                        var code = root.GetProperty("code").GetInt32();

                        if (code == 429)
                            throw new RateLimitException(message);
                        else if (code == 409)
                            throw new AuthException("Email already registered");
                        else if (code == 400)
                            throw new ValidationException(message);
                        else
                            throw new AuthException(message);
                    }

                    return new RegisterResponseDto
                    {
                        Success = true,
                        UserId = root.GetProperty("user_id").GetGuid(),
                        Email = request.Email,
                        VerificationToken = root.GetProperty("verification_token").GetString(),
                        Message = root.GetProperty("message").GetString()
                    };
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Registration failed for email: {Email}", request.Email);
                throw;
            }
        }

        public async Task<RefreshTokenResponseDto> RefreshTokenAsync(RefreshTokenRequestDto request)
        {
            try
            {
                var principal = _jwtService.ValidateRefreshToken(request.RefreshToken);
                if (principal == null)
                {
                    throw new AuthException("Invalid refresh token");
                }

                var refreshJti = principal.FindFirst("jti")?.Value;
                var requestId = Guid.NewGuid();

                var result = await _databaseFunctionService.RefreshJwtTokenAsync(
                    refreshJti,
                    null,
                    requestId
                );

                using (result)
                {
                    var root = result.RootElement;

                    if (!root.GetProperty("success").GetBoolean())
                    {
                        var error = root.GetProperty("error").GetString();
                        var message = root.GetProperty("message").GetString();
                        throw new AuthException(message);
                    }

                    var userId = root.GetProperty("user_id").GetGuid();
                    var roles = root.GetProperty("roles").EnumerateArray()
                        .Select(r => r.GetString())
                        .ToList();

                    var tokens = root.GetProperty("tokens");
                    var newAccessJti = tokens.GetProperty("access_token_jti").GetString();
                    var expiresIn = tokens.GetProperty("expires_in").GetInt32();

                    // Get user email from principal
                    var email = principal.FindFirst("email")?.Value ?? "";

                    // Generate actual JWT token
                    var roleEnum = Enum.Parse<RoleTypeEnum>(roles.FirstOrDefault() ?? "Customer", true);
                    var accessToken = _jwtService.GenerateAccessToken(userId, email, roleEnum, newAccessJti);

                    return new RefreshTokenResponseDto
                    {
                        AccessToken = accessToken,
                        RefreshToken = request.RefreshToken,
                        ExpiresIn = expiresIn
                    };
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Token refresh failed");
                throw;
            }
        }

        public async Task<bool> LogoutAsync(string jti)
        {
            try
            {
                var requestId = Guid.NewGuid();
                var result = await _databaseFunctionService.LogoutSessionAsync(jti, "user_logout", requestId);

                using (result)
                {
                    var root = result.RootElement;
                    return root.GetProperty("success").GetBoolean();
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Logout failed for JTI: {Jti}", jti);
                return false;
            }
        }

        public async Task<bool> RevokeAllSessionsAsync(Guid userId)
        {
            try
            {
                var sessions = await _sessionRepository.GetActiveSessionsByUserIdAsync(userId);

                foreach (var session in sessions)
                {
                    await LogoutAsync(session.Jti);
                }

                return true;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to revoke all sessions for user: {UserId}", userId);
                return false;
            }
        }

        public async Task<bool> ValidateTokenAsync(string token)
        {
            try
            {
                var principal = _jwtService.ValidateToken(token);
                if (principal == null)
                {
                    return false;
                }

                var jti = principal.FindFirst("jti")?.Value;

                var session = await _sessionRepository.GetByJtiAsync(jti);
                if (session == null || !session.IsActive || session.ExpiresAt < DateTime.UtcNow)
                {
                    return false;
                }

                return true;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Token validation failed");
                return false;
            }
        }

        public async Task<AuthResultDto> AuthenticateAsync(string email, string password)
        {
            try
            {
                var loginRequest = new LoginRequestDto
                {
                    Email = email,
                    Password = password
                };

                var loginResult = await LoginAsync(loginRequest);

                return new AuthResultDto
                {
                    Success = true,
                    UserId = loginResult.User.UserId,
                    AccessToken = loginResult.AccessToken,
                    RefreshToken = loginResult.RefreshToken,
                    ExpiresIn = loginResult.ExpiresIn,
                    TokenType = "Bearer",
                    Message = "Authentication successful"
                };
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Authentication failed for email: {Email}", email);
                return new AuthResultDto
                {
                    Success = false,
                    Error = "Authentication failed",
                    Message = ex.Message
                };
            }
        }

        private async Task<JwtSession> CreateSessionAsync(Guid userId, DeviceInfoDto deviceInfo)
        {
            var session = new JwtSession
            {
                SessionId = Guid.NewGuid(),
                UserId = userId,
                Jti = Guid.NewGuid().ToString(),
                RefreshJti = Guid.NewGuid().ToString(),
                DeviceId = deviceInfo?.DeviceId,
                DeviceName = deviceInfo?.DeviceName,
                DeviceType = deviceInfo?.DeviceType,
                IpAddress = deviceInfo?.IpAddress,
                UserAgent = deviceInfo?.UserAgent,
                Location = deviceInfo?.Location != null ? JsonConvert.SerializeObject(deviceInfo.Location) : null,
                CreatedAt = DateTime.UtcNow,
                LastAccessedAt = DateTime.UtcNow,
                ExpiresAt = DateTime.UtcNow.AddDays(30),
                IsActive = true
            };

            return await _sessionRepository.CreateAsync(session);
        }

        private async Task LogLoginAttempt(string identifier, bool success, string? failureReason, DeviceInfoDto deviceInfo, string fingerprint)
        {
            var attempt = new LoginAttempt
            {
                AttemptId = Guid.NewGuid(),
                Identifier = identifier,
                AuthProvider = AuthProviderEnum.Password,
                Success = success,
                FailureReason = failureReason,
                IpAddress = deviceInfo?.IpAddress ?? "0.0.0.0",
                UserAgent = deviceInfo?.UserAgent,
                AttemptedAt = DateTime.UtcNow,
                Fingerprint = fingerprint
            };

            await _loginAttemptRepository.CreateAsync(attempt);
        }

        private string GenerateSecureToken()
        {
            var randomBytes = new byte[32];
            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(randomBytes);
            }
            return Convert.ToBase64String(randomBytes);
        }
    }
}