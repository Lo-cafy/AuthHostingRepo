using System;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using AuthService.Application.Interfaces;
using AuthService.Application.DTOs.Account;
using AuthService.Infrastructure.Interfaces;
using AuthService.Domain.Entities;
using AuthService.Domain.Enums;
using AuthService.Shared.Exceptions;
using System.Security.Cryptography;
using System.Text;
using Newtonsoft.Json.Linq;

namespace AuthService.Application.Services
{
    public class AccountService : IAccountService
    {
        private readonly IDatabaseFunctionService _databaseFunctionService;
        private readonly IUserCredentialRepository _credentialRepository;
        private readonly ISecurityTokenRepository _tokenRepository;
        private readonly IPasswordService _passwordService;
        private readonly ILogger<AccountService> _logger;

        public AccountService(
            IDatabaseFunctionService databaseFunctionService,
            IUserCredentialRepository credentialRepository,
            ISecurityTokenRepository tokenRepository,
            IPasswordService passwordService,
            ILogger<AccountService> logger)
        {
            _databaseFunctionService = databaseFunctionService;
            _credentialRepository = credentialRepository;
            _tokenRepository = tokenRepository;
            _passwordService = passwordService;
            _logger = logger;
        }

        public async Task<bool> VerifyEmailAsync(VerifyEmailDto request)
        {
            try
            {
                var requestId = Guid.NewGuid();
                var result = await _databaseFunctionService.VerifyEmailAsync(request.Token, requestId);

                using (result)
                {
                    var root = result.RootElement;

                    if (!root.GetProperty("success").GetBoolean())
                    {
                        var message = root.GetProperty("message").GetString();
                        throw new ValidationException(message);
                    }

                    _logger.LogInformation("Email verified for user: {UserId}",
                        root.GetProperty("user_id").GetGuid());

                    return true;
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Email verification failed");
                throw;
            }
        }

        public async Task<bool> RequestPasswordResetAsync(string email)
        {
            try
            {
                var credential = await _credentialRepository.GetByEmailAsync(email);
                if (credential == null)
                {
                    // Don't reveal if email exists
                    _logger.LogInformation("Password reset requested for non-existent email: {Email}", email);
                    return true;
                }

                // Generate reset token
                var resetToken = GenerateSecureToken();
                var tokenHash = HashToken(resetToken);

                var securityToken = new SecurityToken
                {
                    TokenId = Guid.NewGuid(),
                    UserId = credential.UserId,
                    TokenType = TokenTypeEnum.ResetPassword,
                    TokenHash = tokenHash,
                    ExpiresAt = DateTime.UtcNow.AddHours(1),
                    CreatedAt = DateTime.UtcNow,
                    Metadata = new Dictionary<string, object>() 
                };

                await _tokenRepository.CreateAsync(securityToken);

                // TODO: Send email with reset link containing resetToken
                _logger.LogInformation("Password reset token generated for user: {UserId}", credential.UserId);

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
                // Find token by hash
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

                // Validate new password
                _passwordService.ValidatePasswordStrength(request.NewPassword);

                // Get user credential
                var credential = await _credentialRepository.GetByUserIdAsync(token.UserId);
                if (credential == null)
                {
                    throw new ValidationException("User not found");
                }

                // Generate password salt and hash (matching database stored procedure format)
                var passwordSalt = GeneratePasswordSalt();
                var passwordHash = BCrypt.Net.BCrypt.HashPassword(request.NewPassword + passwordSalt, 12);

                // Update password
                credential.PasswordHash = passwordHash;
                credential.PasswordSalt = passwordSalt;
                credential.PasswordChangedAt = DateTime.UtcNow;
                credential.FailedAttempts = 0;
                credential.LockedUntil = null;
                await _credentialRepository.UpdateAsync(credential);

                // Mark token as used
                token.UsedAt = DateTime.UtcNow;
                await _tokenRepository.UpdateAsync(token);

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

                // Verify current password with salt
                var currentPasswordWithSalt = request.CurrentPassword + credential.PasswordSalt;
                if (!BCrypt.Net.BCrypt.Verify(currentPasswordWithSalt, credential.PasswordHash))
                {
                    throw new ValidationException("Current password is incorrect");
                }

                // Validate new password
                _passwordService.ValidatePasswordStrength(request.NewPassword);

                // Generate new salt and hash
                var passwordSalt = GeneratePasswordSalt();
                var passwordHash = BCrypt.Net.BCrypt.HashPassword(request.NewPassword + passwordSalt, 12);

                // Update password
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

        private string GenerateSecureToken()
        {
            var randomBytes = new byte[32];
            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(randomBytes);
            }
            return Convert.ToBase64String(randomBytes);
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