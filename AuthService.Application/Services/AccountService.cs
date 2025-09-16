using System;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using AuthService.Application.Interfaces;
using AuthService.Application.DTOs.Account;
using AuthService.Infrastructure.Interfaces;
using AuthService.Domain.Entities;
using AuthService.Domain.Enums;
using System.ComponentModel.DataAnnotations;

namespace AuthService.Application.Services
{
    public class AccountService : IAccountService
    {
        private readonly IUserCredentialRepository _credentialRepository;
        private readonly ISecurityTokenRepository _tokenRepository;
        private readonly IPasswordService _passwordService;
        private readonly ILogger<AccountService> _logger;

        public AccountService(
            IUserCredentialRepository credentialRepository,
            ISecurityTokenRepository tokenRepository,
            IPasswordService passwordService,
            ILogger<AccountService> logger)
        {
            _credentialRepository = credentialRepository;
            _tokenRepository = tokenRepository;
            _passwordService = passwordService;
            _logger = logger;
        }

        public async Task<bool> VerifyEmailAsync(VerifyEmailDto request)
        {
            try
            {
                var token = await _tokenRepository.GetByTokenHashAsync(request.Token);

                if (token == null || token.TokenType != TokenTypeEnum.EmailVerification)
                {
                    throw new ValidationException("Invalid verification token");
                }

                if (token.ExpiresAt < DateTime.UtcNow)
                {
                    throw new ValidationException("Verification token has expired");
                }

                if (token.UsedAt.HasValue)
                {
                    throw new ValidationException("Verification token has already been used");
                }

                // Mark token as used
                token.UsedAt = DateTime.UtcNow;
                await _tokenRepository.UpdateAsync(token);

                // Update user email verification status
                var credential = await _credentialRepository.GetByUserIdAsync(token.UserId);
                if (credential != null)
                {
                    // You might need to add IsEmailVerified to UserCredential or maintain it separately
                    await _credentialRepository.UpdateAsync(credential);
                }

                return true;
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
                    return true;
                }

                // Generate reset token
                var resetToken = Guid.NewGuid().ToString();
                var tokenHash = _passwordService.HashPassword(resetToken); // Reuse password hashing

                var securityToken = new SecurityToken
                {
                    TokenId = Guid.NewGuid(),
                    UserId = credential.UserId,
                    TokenType = TokenTypeEnum.ResetPassword,
                    TokenHash = tokenHash,
                    ExpiresAt = DateTime.UtcNow.AddHours(1),
                    CreatedAt = DateTime.UtcNow,
                    Metadata = "{}"
                };

                await _tokenRepository.CreateAsync(securityToken);

                // In production, send email with reset link
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
                var token = await _tokenRepository.GetByTokenHashAsync(request.Token);

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

                // Update password
                var credential = await _credentialRepository.GetByUserIdAsync(token.UserId);
                if (credential == null)
                {
                    throw new ValidationException("User not found");
                }

                credential.PasswordHash = _passwordService.HashPassword(request.NewPassword);
                credential.PasswordChangedAt = DateTime.UtcNow;
                credential.FailedAttempts = 0;
                credential.LockedUntil = null;
                await _credentialRepository.UpdateAsync(credential);

                // Mark token as used
                token.UsedAt = DateTime.UtcNow;
                await _tokenRepository.UpdateAsync(token);

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

                // Verify current password
                if (!_passwordService.VerifyPassword(request.CurrentPassword, credential.PasswordHash))
                {
                    throw new ValidationException("Current password is incorrect");
                }

                // Validate new password
                _passwordService.ValidatePasswordStrength(request.NewPassword);

                // Update password
                credential.PasswordHash = _passwordService.HashPassword(request.NewPassword);
                credential.PasswordChangedAt = DateTime.UtcNow;
                await _credentialRepository.UpdateAsync(credential);

                return true;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Password change failed");
                throw;
            }
        }
    }
}