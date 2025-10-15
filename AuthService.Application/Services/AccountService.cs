using AuthService.Application.DTOs.Account;
using AuthService.Application.DTOs.Auth;
using AuthService.Application.Exceptions;
using AuthService.Application.Interfaces;
using AuthService.Domain.Entities;
using AuthService.Domain.Enums;
using AuthService.Infrastructure.Interfaces;
using AuthService.Infrastructure.Repositories;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using static EmailService.Grpc.EmailService;

namespace AuthService.Application.Services
{
    public class AccountService : IAccountService
    {
        private readonly IDatabaseFunctionService _databaseFunctionService;
        private readonly IUserCredentialRepository _credentialRepository;
        private readonly ISecurityTokenRepository _tokenRepository;
        private readonly IPasswordService _passwordService;
        private readonly ILogger<AccountService> _logger;
        private readonly EmailService.Grpc.EmailService.EmailServiceClient _emailServiceClient;
        private readonly IConfiguration _configuration;

        public AccountService(
            IDatabaseFunctionService databaseFunctionService,
            IUserCredentialRepository credentialRepository,
            ISecurityTokenRepository tokenRepository,
            IPasswordService passwordService,
            ILogger<AccountService> logger,
            EmailService.Grpc.EmailService.EmailServiceClient emailServiceClient,
            IConfiguration configuration)
        {
            _databaseFunctionService = databaseFunctionService;
            _credentialRepository = credentialRepository;
            _tokenRepository = tokenRepository;
            _passwordService = passwordService;
            _logger = logger;
            _emailServiceClient = emailServiceClient;
            _configuration = configuration;
        }

        public async Task<bool> RequestPasswordResetAsync(string email)
        {
            try
            {
                var credential = await _credentialRepository.GetByEmailAsync(email);
                if (credential == null)
                {
                    _logger.LogInformation("Password reset requested for non-existent email: {Email}", email);
                    return true;
                }

                var resetToken = GenerateSecureToken();
                var tokenHash = HashToken(resetToken);

                var securityToken = new SecurityToken
                {
                    UserId = credential.UserId,
                    TokenType = TokenTypeEnum.ResetPassword,
                    TokenHash = tokenHash,
                    TokenPlain = resetToken,
                    ExpiresAt = DateTime.UtcNow.AddHours(1),
                    CreatedAt = DateTime.UtcNow,
                    Metadata = new Dictionary<string, object>()
                };

                await _tokenRepository.CreateAsync(securityToken);
                _logger.LogInformation("Password reset token generated for user: {UserId}", credential.UserId);

                try
                {
                    var clientAppUrl = _configuration["AppSettings:ClientAppUrl"];
                    if (string.IsNullOrEmpty(clientAppUrl))
                    {
                        _logger.LogError("ClientAppUrl is not configured in appsettings.json");
                        return true;
                    }

                    var resetLink = $"{clientAppUrl}/reset-password?token={resetToken}";

                    var emailRequest = new EmailService.Grpc.SendEmailRequest
                    {
                        ToEmail = email,
                        Subject = "Reset Your Password",
                        ViewName = "PasswordReset",
                        ModelJson = System.Text.Json.JsonSerializer.Serialize(new { ResetLink = resetLink })
                    };

                    await _emailServiceClient.SendEmailAsync(emailRequest);
                    _logger.LogInformation("Password reset email sent to: {Email}", email);
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Failed to send password reset email to {Email}", email);
                }

                return true;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Password reset request failed");
                throw;
            }
        }

        public async Task<bool> ResetPasswordAsync(ResetPasswordDto request)
        {
            try
            {
                var tokenHash = HashToken(request.Token);
                var token = await _tokenRepository.GetByTokenHashAsync(tokenHash);

                if (token == null || token.TokenType != TokenTypeEnum.ResetPassword)
                {
                    throw new ValidationException("Invalid reset token");
                }

                if (token.ExpiresAt < DateTime.UtcNow)
                {
                    throw new ValidationException("Reset token has expired");
                }

                if (token.UsedAt.HasValue)
                {
                    throw new ValidationException("Reset token has already been used");
                }

                _passwordService.ValidatePasswordStrength(request.NewPassword);

                var credential = await _credentialRepository.GetByUserIdAsync(token.UserId);
                if (credential == null)
                {
                    throw new ValidationException("User not found");
                }

                var passwordSalt = GeneratePasswordSalt();
                var passwordHash = BCrypt.Net.BCrypt.HashPassword(request.NewPassword + passwordSalt, 12);

                credential.PasswordHash = passwordHash;
                credential.PasswordSalt = passwordSalt;
                credential.PasswordChangedAt = DateTime.UtcNow;
                credential.FailedAttempts = 0;
                credential.LockedUntil = null;
                await _credentialRepository.UpdateAsync(credential);

                await _tokenRepository.MarkAsUsedAsync(token.TokenId);

                _logger.LogInformation("Password reset completed for user: {UserId}", token.UserId);

                return true;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Password reset failed");
                throw;
            }
        }

        public async Task<bool> ChangePasswordAsync(ChangePasswordDto request)
        {
            try
            {
                var credential = await _credentialRepository.GetByUserIdAsync(request.UserId);
                if (credential == null)
                {
                    throw new ValidationException("User not found");
                }
                var currentPasswordWithSalt = request.CurrentPassword + credential.PasswordSalt;
                if (!BCrypt.Net.BCrypt.Verify(currentPasswordWithSalt, credential.PasswordHash))
                {
                    throw new ValidationException("Current password is incorrect");
                }

                _passwordService.ValidatePasswordStrength(request.NewPassword);

                var passwordSalt = GeneratePasswordSalt();
                var passwordHash = BCrypt.Net.BCrypt.HashPassword(request.NewPassword + passwordSalt, 12);

                credential.PasswordHash = passwordHash;
                credential.PasswordSalt = passwordSalt;
                credential.PasswordChangedAt = DateTime.UtcNow;
                await _credentialRepository.UpdateAsync(credential);

                _logger.LogInformation("Password changed for user: {UserId}", request.UserId);

                return true;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Password change failed");
                throw;
            }
        }

        public async Task<RegisterResponseDto> RegisterAsync(RegisterRequestDto request)
        {
            try
            {
                if (await _credentialRepository.EmailExistsAsync(request.Email))
                {
                    return new RegisterResponseDto { Success = false, Message = "Email already exists" };
                }

                var passwordSalt = GeneratePasswordSalt();
                var passwordHash = BCrypt.Net.BCrypt.HashPassword(request.Password + passwordSalt, 12);

                var userCredential = new UserCredential
                {
                    UserId = request.UserId,
                    Email = request.Email,
                    PasswordHash = passwordHash,
                    PasswordSalt = passwordSalt,
                    Role = RoleType.Customer,
                    IsActive = true,
                    CreatedAt = DateTime.UtcNow,
                    UpdatedAt = DateTime.UtcNow
                };

                var created = await _credentialRepository.CreateAsync(userCredential);

                _logger.LogInformation("User registered successfully with Email {Email}", request.Email);

                return new RegisterResponseDto
                {
                    Success = true,
                    Message = "User registered successfully",
                    UserId = created.UserId
                };
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "User registration failed for {Email}", request.Email);
                return new RegisterResponseDto { Success = false, Message = "Internal server error" };
            }
        }

        public async Task<RegisterResponseDto> RegisterGrpcAsync(RegisterRequestDto request)
        {
            try
            {
                // Check if email already exists (optional)
                // if (await _userRepository.EmailExistsAsync(request.Email)) 
                //     return new RegisterResponseDto { Success = false, Message = "Email already exists" };

                var passwordSalt = GeneratePasswordSalt();
                var passwordHash = request.Password;

                var result = await _credentialRepository.RegisterUserEnhancedAsync(
                    userId: request.UserId,
                    email: request.Email,
                    passwordHash: passwordHash,
                    passwordSalt: passwordSalt,
                    role: "customer",
                    phoneNumber: request.PhoneNumber,
                    referredBy: request.ReferredBy,
                    createdIp: request.ClientIp
                );

                _logger.LogInformation("User registered successfully with Email {Email}", request.Email);

                return new RegisterResponseDto
                {
                    Success = true,
                    Message = "User registered successfully",
                    UserId = result.UserId,
                    CredentialId = result.CredentialId  
                };
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "User registration failed for {Email}", request.Email);
                return new RegisterResponseDto { Success = false, Message = "Internal server error" };
            }
        }





        private string GenerateSecureToken()
        {
            var randomBytes = new byte[32];
            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(randomBytes);
            }
            return Convert.ToBase64String(randomBytes)
                .Replace('+', '-')
                .Replace('/', '_')
                .TrimEnd('=');
        }

        private string GeneratePasswordSalt()
        {
            var saltBytes = new byte[32];
            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(saltBytes);
            }
            return Convert.ToBase64String(saltBytes);
        }

        private string HashToken(string token)
        {
            using (var sha256 = SHA256.Create())
            {
                var hashedBytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(token));
                return Convert.ToHexString(hashedBytes).ToLower();
            }
        }
    }
}