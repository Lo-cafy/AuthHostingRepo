using System;
using System.Security.Cryptography;
using System.Text.RegularExpressions;
using AuthService.Application.Interfaces;
using AuthService.Shared.Exceptions;
using Microsoft.AspNetCore.Cryptography.KeyDerivation;
using BCrypt.Net;

namespace AuthService.Application.Services
{
    public class PasswordService : IPasswordService
    {
        private const int SaltSize = 128 / 8;
        private const int KeySize = 256 / 8;
        private const int Iterations = 10000;

        public string HashPassword(string password)
        {
            // For compatibility with stored procedures, use BCrypt
            return BCrypt.Net.BCrypt.HashPassword(password, 12);
        }

        public string HashPasswordWithSalt(string password, string salt)
        {
            // For database stored procedure compatibility
            var combinedPassword = password + salt;
            return BCrypt.Net.BCrypt.HashPassword(combinedPassword, 12);
        }

        public bool VerifyPassword(string password, string hashedPassword)
        {
            try
            {
                // Try BCrypt first (for stored procedure compatibility)
                return BCrypt.Net.BCrypt.Verify(password, hashedPassword);
            }
            catch
            {
                // Fallback to PBKDF2 for legacy passwords
                try
                {
                    var hashBytes = Convert.FromBase64String(hashedPassword);

                    var salt = new byte[SaltSize];
                    Array.Copy(hashBytes, 0, salt, 0, SaltSize);

                    var hash = KeyDerivation.Pbkdf2(
                        password: password,
                        salt: salt,
                        prf: KeyDerivationPrf.HMACSHA256,
                        iterationCount: Iterations,
                        numBytesRequested: KeySize
                    );

                    for (int i = 0; i < KeySize; i++)
                    {
                        if (hashBytes[i + SaltSize] != hash[i])
                            return false;
                    }

                    return true;
                }
                catch
                {
                    return false;
                }
            }
        }

        public bool VerifyPasswordWithSalt(string password, string hashedPassword, string salt)
        {
            var combinedPassword = password + salt;
            return BCrypt.Net.BCrypt.Verify(combinedPassword, hashedPassword);
        }

        public void ValidatePasswordStrength(string password)
        {
            if (string.IsNullOrWhiteSpace(password))
                throw new ValidationException("Password cannot be empty");

            if (password.Length < 8)
                throw new ValidationException("Password must be at least 8 characters long");

            if (password.Length > 128)
                throw new ValidationException("Password must not exceed 128 characters");

            if (!Regex.IsMatch(password, @"[A-Z]"))
                throw new ValidationException("Password must contain at least one uppercase letter");

            if (!Regex.IsMatch(password, @"[a-z]"))
                throw new ValidationException("Password must contain at least one lowercase letter");

            if (!Regex.IsMatch(password, @"[0-9]"))
                throw new ValidationException("Password must contain at least one number");

            if (!Regex.IsMatch(password, @"[^A-Za-z0-9]"))
                throw new ValidationException("Password must contain at least one special character");

            var commonPasswords = new[] { "password", "123456", "qwerty", "letmein", "welcome", "admin" };
            if (Array.Exists(commonPasswords, p => password.ToLower().Contains(p)))
                throw new ValidationException("Password is too common");
        }
    }
}