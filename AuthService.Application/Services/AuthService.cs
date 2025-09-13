using System;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using AuthService.Application.Interfaces;
using AuthService.Application.DTOs.Auth;
using AuthService.Infrastructure.Interfaces;
using AuthService.Domain.Entities;
using AuthService.Shared.Exceptions;
using System.Security.Cryptography;
using AuthService.Application.DTOs.Common;
using System.Text;
using Newtonsoft.Json;
using AuthService.Infrastructure.Repositories;

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

        public async Task<LoginResponseDto> LoginAsync(LoginRequestDto request)
        {
            try
            {
                // Generate fingerprint
                var fingerprint = _fingerprintService.GenerateFingerprint(request.DeviceInfo);

                // Check rate limiting
                var recentFailures = await _loginAttemptRepository.GetRecentFailuresAsync(fingerprint, 15);
                if (recentFailures >= 5)
                {
                    await LogLoginAttempt(request.Email, false, "rate_limited", request.DeviceInfo, fingerprint);
                    throw new RateLimitException("Too many failed attempts. Try again in 15 minutes.");
                }

                // Get user credentials
                var credential = await _credentialRepository.GetByEmailAsync(request.Email);
                if (credential == null)
                {
                    await LogLoginAttempt(request.Email, false, "user_not_found", request.DeviceInfo, fingerprint);
                    throw new AuthException("Invalid email or password");
                }

                // Check if account is locked
                if (credential.LockedUntil.HasValue && credential.LockedUntil > DateTime.UtcNow)
                {
                    await LogLoginAttempt(request.Email, false, "account_locked", request.DeviceInfo, fingerprint);
                    throw new AuthException($"Account is locked until {credential.LockedUntil}");
                }

                // Verify password
                if (!_passwordService.VerifyPassword(request.Password, credential.PasswordHash))
                {
                    // Update failed attempts
                    credential.FailedAttempts++;
                    if (credential.FailedAttempts >= 5)
                    {
                        credential.LockedUntil = DateTime.UtcNow.AddMinutes(30);
                    }
                    await _credentialRepository.UpdateAsync(credential);

                    await LogLoginAttempt(request.Email, false, "invalid_password", request.DeviceInfo, fingerprint);
                    throw new AuthException("Invalid email or password");
                }

                // Reset failed attempts on successful login
                if (credential.FailedAttempts > 0)
                {
                    credential.FailedAttempts = 0;
                    credential.LockedUntil = null;
                    await _credentialRepository.UpdateAsync(credential);
                }

                // Create JWT session
                var session = await CreateSessionAsync(credential.UserId, request.DeviceInfo);

                // Generate tokens
                var accessToken = _jwtService.GenerateAccessToken(credential.UserId, credential.Email, new[] { credential.Role }, session.Jti);
                                var refreshToken = _jwtService.GenerateRefreshToken(credential.UserId, session.RefreshJti);

                // Log successful login
                await LogLoginAttempt(request.Email, true, null, request.DeviceInfo, fingerprint);

                return new LoginResponseDto
                {
                    AccessToken = accessToken,
                    RefreshToken = refreshToken,
                    ExpiresIn = 3600,
                    UserId = credential.UserId,
                    Email = credential.Email,
                    Roles = new[] { credential.Role }
                };
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
                    Role = request.Role ?? "customer",
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

        public async Task LogoutAsync(string jti)
        {
            var session = await _sessionRepository.GetByJtiAsync(jti);
            if (session != null && session.IsActive)
            {
                session.IsActive = false;
                session.RevokedAt = DateTime.UtcNow;
                session.RevokeReason = "User logout";
                await _sessionRepository.UpdateAsync(session);
            }
        }

        public async Task<RefreshTokenResponseDto> RefreshTokenAsync(RefreshTokenRequestDto request)
        {
            try
            {
                // Validate refresh token
                var principal = _jwtService.ValidateRefreshToken(request.RefreshToken);
                if (principal == null)
                {
                    throw new AuthException("Invalid refresh token");
                }

                var refreshJti = principal.FindFirst("jti")?.Value;
                var userId = Guid.Parse(principal.FindFirst("sub")?.Value);

                // Get session
                var session = await _sessionRepository.GetByRefreshJtiAsync(refreshJti);
                if (session == null || !session.IsActive || session.ExpiresAt < DateTime.UtcNow)
                {
                    throw new AuthException("Invalid or expired session");
                }

                // Get user
                var credential = await _credentialRepository.GetByUserIdAsync(userId);
                if (credential == null || !credential.IsActive)
                {
                    throw new AuthException("User not found or inactive");
                }

                // Update session
                session.LastAccessedAt = DateTime.UtcNow;
                await _sessionRepository.UpdateAsync(session);

                // Generate new access token
                var accessToken = _jwtService.GenerateAccessToken(
                    credential.UserId, 
                    credential.Email, 
                    new[] { credential.Role }, 
                    session.Jti
                );

                return new RefreshTokenResponseDto
                {
                    AccessToken = accessToken,
                    ExpiresIn = 3600
                };
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Token refresh failed");
                throw;
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

        private async Task LogLoginAttempt(string identifier, bool success, string failureReason, DeviceInfoDto deviceInfo, string fingerprint)
        {
            var attempt = new LoginAttempt
            {
                AttemptId = Guid.NewGuid(),
                Identifier = identifier,
                AuthProvider = Domain.Enums.AuthProviderEnum.Password,
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