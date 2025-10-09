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
using AuthService.Application.Exceptions;
using System.Security.Cryptography;
using System.Text;
using Newtonsoft.Json;
using Microsoft.AspNetCore.Http;

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
        private readonly IHttpContextAccessor _httpContextAccessor;
        private readonly ILogger<AuthService> _logger;

        public AuthService(
            IDatabaseFunctionService databaseFunctionService,
            IUserCredentialRepository credentialRepository,
            IJwtService jwtService,
            IPasswordService passwordService,
            IJwtSessionRepository sessionRepository,
            ILoginAttemptRepository loginAttemptRepository,
            IDigitalFingerprintService fingerprintService,
              IHttpContextAccessor httpContextAccessor,
            ILogger<AuthService> logger)
        {
            _databaseFunctionService = databaseFunctionService;
            _credentialRepository = credentialRepository;
            _jwtService = jwtService;
            _passwordService = passwordService;
            _sessionRepository = sessionRepository;
            _loginAttemptRepository = loginAttemptRepository;
            _fingerprintService = fingerprintService;
            _httpContextAccessor = httpContextAccessor;
            _logger = logger;
        }
        public async Task<LoginResponseDto> LoginAsync(LoginRequestDto request, DeviceInfoDto? deviceInfo = null)
        {
            try
            {
                deviceInfo ??= new DeviceInfoDto
                {
                    IpAddress = "127.0.0.1",
                    UserAgent = "Unknown"
                };

                var requestId = Guid.NewGuid();

                var deviceInfoForSP = new
                {
                    ip_address = deviceInfo.IpAddress,
                    user_agent = deviceInfo.UserAgent,
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
                     if (!root.TryGetProperty("success", out var successElement) || !successElement.GetBoolean())
                    {
                        
                        var message = root.TryGetProperty("message", out var msgElement) ? msgElement.GetString() : "Invalid credentials";

                        if (root.TryGetProperty("code", out var codeElement) && codeElement.TryGetInt32(out int code))
                        {
                            if (code == 429) throw new RateLimitException(message);
                        }

                        throw new AuthException(message ?? "Authentication failed");
                    }

               

                    var userId = root.TryGetProperty("user_id", out var userIdElement) ? userIdElement.GetInt32() : 0;
                    var email = root.TryGetProperty("email", out var emailElement) ? emailElement.GetString() : string.Empty;
                    var emailVerified = root.TryGetProperty("email_verified", out var emailVerifiedElement) && emailVerifiedElement.GetBoolean();

                    var roles = new List<string>();
                    if (root.TryGetProperty("roles", out var rolesElement) && rolesElement.ValueKind == JsonValueKind.Array)
                    {
                        roles = rolesElement.EnumerateArray().Select(r => r.GetString() ?? string.Empty).ToList();
                    }

                    string accessJti = string.Empty;
                    string refreshJti = string.Empty;
                    double expiresIn = 3600; // Default expiry

                    if (root.TryGetProperty("tokens", out var tokensElement))
                    {
                        accessJti = tokensElement.TryGetProperty("access_token_jti", out var accessJtiElement) ? accessJtiElement.GetString() : string.Empty;
                        refreshJti = tokensElement.TryGetProperty("refresh_token_jti", out var refreshJtiElement) ? refreshJtiElement.GetString() : string.Empty;
                        expiresIn = tokensElement.TryGetProperty("expires_in", out var expiresInElement) ? expiresInElement.GetDouble() : 3600;
                    }

                    var roleEnum = Enum.TryParse<RoleTypeEnum>(roles.FirstOrDefault() ?? "Customer", true, out var parsedRole) ? parsedRole : RoleTypeEnum.Customer;

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

                    var userId = root.GetProperty("user_id").GetInt32();
                    var roles = root.GetProperty("roles").EnumerateArray()
                        .Select(r => r.GetString())
                        .ToList();

                    var tokens = root.GetProperty("tokens");
                    var newAccessJti = tokens.GetProperty("access_token_jti").GetString();
                    var expiresIn = tokens.GetProperty("expires_in").GetInt32();

                  
                    var email = principal.FindFirst("email")?.Value ?? "";

                  
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

        public async Task<bool> RevokeAllSessionsAsync(int userId)
        {
            try
            {
                
                var userIdInt = int.Parse(userId.ToString("N").Substring(0, 8), System.Globalization.NumberStyles.HexNumber);
                var sessions = await _sessionRepository.GetActiveSessionsByUserIdAsync(userIdInt);

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

        public async Task<JwtSession> CreateSessionAsync(int userId, DeviceInfoDto deviceInfo)
        {
            var session = new JwtSession
            {
                SessionId = new int(),
                UserId = userId,
                Jti = new int().ToString(),
                RefreshJti = new int().ToString(),
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

        public async Task LogLoginAttempt(string identifier, bool success, string? failureReason, DeviceInfoDto deviceInfo, string fingerprint)
        {
            var attempt = new LoginAttempt
            {
                AttemptId = new int(),
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

        public string GenerateSecureToken()
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