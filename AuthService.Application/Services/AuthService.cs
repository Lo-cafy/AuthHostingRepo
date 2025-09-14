using System;
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
        private readonly IUserCredentialRepository _credentialRepository;
        private readonly IJwtService _jwtService;
        private readonly IPasswordService _passwordService;
        private readonly IJwtSessionRepository _sessionRepository;
        private readonly ILoginAttemptRepository _loginAttemptRepository;
        private readonly IDigitalFingerprintService _fingerprintService;
        private readonly ILogger<AuthService> _logger;

        public AuthService(
            IUserCredentialRepository credentialRepository,
            IJwtService jwtService,
            IPasswordService passwordService,
            IJwtSessionRepository sessionRepository,
            ILoginAttemptRepository loginAttemptRepository,
            IDigitalFingerprintService fingerprintService,
            ILogger<AuthService> logger)
        {
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
                    IpAddress = "0.0.0.0",
                    UserAgent = "Unknown"
                };

                var fingerprint = _fingerprintService.GenerateFingerprint(deviceInfo);

                var recentFailures = await _loginAttemptRepository.GetRecentFailuresAsync(fingerprint, 15);
                if (recentFailures >= 5)
                {
                    await LogLoginAttempt(request.Email, false, "rate_limited", deviceInfo, fingerprint);
                    throw new RateLimitException("Too many failed attempts. Try again in 15 minutes.");
                }

                var credential = await _credentialRepository.GetByEmailAsync(request.Email);
                if (credential == null)
                {
                    await LogLoginAttempt(request.Email, false, "user_not_found", deviceInfo, fingerprint);
                    throw new AuthException("Invalid email or password");
                }

                if (credential.LockedUntil.HasValue && credential.LockedUntil > DateTime.UtcNow)
                {
                    await LogLoginAttempt(request.Email, false, "account_locked", deviceInfo, fingerprint);
                    throw new AuthException($"Account is locked until {credential.LockedUntil}");
                }

                if (!_passwordService.VerifyPassword(request.Password, credential.PasswordHash))
                {
                    credential.FailedAttempts++;
                    if (credential.FailedAttempts >= 5)
                    {
                        credential.LockedUntil = DateTime.UtcNow.AddMinutes(30);
                    }
                    await _credentialRepository.UpdateAsync(credential);

                    await LogLoginAttempt(request.Email, false, "invalid_password", deviceInfo, fingerprint);
                    throw new AuthException("Invalid email or password");
                }

                if (credential.FailedAttempts > 0)
                {
                    credential.FailedAttempts = 0;
                    credential.LockedUntil = null;
                    await _credentialRepository.UpdateAsync(credential);
                }

                var session = await CreateSessionAsync(credential.UserId, deviceInfo);

                var accessToken = _jwtService.GenerateAccessToken(
                    credential.UserId,
                    credential.Email,
                    Enum.Parse<RoleTypeEnum>(credential.Role),
                    session.Jti
                );
                var refreshToken = _jwtService.GenerateRefreshToken(credential.UserId, session.RefreshJti);

                await LogLoginAttempt(request.Email, true, null, deviceInfo, fingerprint);

                return new LoginResponseDto
                {
                    Success = true,
                    AccessToken = accessToken,
                    RefreshToken = refreshToken,
                    ExpiresIn = 3600,
                    ExpiresAt = DateTime.UtcNow.AddHours(1),
                    User = new UserInfoDto
                    {
                        UserId = credential.UserId,
                        Email = credential.Email,
                        IsEmailVerified = true,
                        Role = Enum.Parse<RoleTypeEnum>(credential.Role)

                    },
                    Role = Enum.Parse<RoleTypeEnum>(credential.Role)

                };
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
                var userId = Guid.Parse(principal.FindFirst("sub")?.Value ?? "");

                var session = await _sessionRepository.GetByRefreshJtiAsync(refreshJti);
                if (session == null || !session.IsActive || session.ExpiresAt < DateTime.UtcNow)
                {
                    throw new AuthException("Invalid or expired session");
                }

                var credential = await _credentialRepository.GetByUserIdAsync(userId);
                if (credential == null || !credential.IsActive)
                {
                    throw new AuthException("User not found or inactive");
                }

                session.LastAccessedAt = DateTime.UtcNow;
                await _sessionRepository.UpdateAsync(session);

                var accessToken = _jwtService.GenerateAccessToken(
                    credential.UserId,
                    credential.Email,
                    Enum.Parse<RoleTypeEnum>(credential.Role),
                    session.Jti
                );

                return new RefreshTokenResponseDto
                {
                    AccessToken = accessToken,
                    RefreshToken = request.RefreshToken,
                    ExpiresIn = 3600
                };
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Token refresh failed");
                throw;
            }
        }

        public async Task<RegisterResponseDto> RegisterAsync(RegisterRequestDto request)
        {
            try
            {
                // Check if email already exists
                if (await _credentialRepository.EmailExistsAsync(request.Email))
                {
                    throw new AuthException("Email already registered");
                }

                // Validate password
                _passwordService.ValidatePasswordStrength(request.Password);

                // Hash password
                var passwordHash = _passwordService.HashPassword(request.Password);

                // Create user
                var userId = Guid.NewGuid();
                var credential = new UserCredential
                {
                    UserId = userId,
                    Email = request.Email.ToLower(),
                    PasswordHash = passwordHash,
                    Role = RoleTypeEnum.Customer.ToString(),
                    IsActive = true,
                    CreatedAt = DateTime.UtcNow,
                    UpdatedAt = DateTime.UtcNow,
                    PasswordChangedAt = DateTime.UtcNow
                };

                await _credentialRepository.CreateAsync(credential);

                // Generate verification token
                var verificationToken = GenerateSecureToken();

                return new RegisterResponseDto
                {
                    Success = true,
                    UserId = userId,
                    Email = credential.Email,
                    VerificationToken = verificationToken,
                    Message = "Registration successful. Please verify your email."
                };
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Registration failed for email: {Email}", request.Email);
                throw;
            }
        }

        public async Task<bool> LogoutAsync(string jti)
        {
            var session = await _sessionRepository.GetByJtiAsync(jti);
            if (session != null && session.IsActive)
            {
                session.IsActive = false;
                session.RevokedAt = DateTime.UtcNow;
                session.RevokeReason = "User logout";
                await _sessionRepository.UpdateAsync(session);
                return true;
            }
            return false;
        }

        public async Task<bool> RevokeAllSessionsAsync(Guid userId)
        {
            var sessions = await _sessionRepository.GetActiveSessionsByUserIdAsync(userId);
            foreach (var session in sessions)
            {
                session.IsActive = false;
                session.RevokedAt = DateTime.UtcNow;
                session.RevokeReason = "All sessions revoked";
                await _sessionRepository.UpdateAsync(session);
            }
            return true;
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

                var userId = Guid.Parse(principal.FindFirst("sub")?.Value ?? "");
                var jti = principal.FindFirst("jti")?.Value;

                var session = await _sessionRepository.GetByJtiAsync(jti);
                if (session == null || !session.IsActive || session.ExpiresAt < DateTime.UtcNow)
                {
                    return false;
                }

                var credential = await _credentialRepository.GetByUserIdAsync(userId);
                return credential != null && credential.IsActive;
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