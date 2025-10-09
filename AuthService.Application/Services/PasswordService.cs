using System;
using System.Security.Cryptography;
using System.Text.RegularExpressions;
using AuthService.Application.Interfaces;
using AuthService.Application.Exceptions;
using Microsoft.AspNetCore.Cryptography.KeyDerivation;

namespace AuthService.Application.Services
{
    public class PasswordService : IPasswordService
    {
        private const int SaltSize = 128 / 8;
        private const int KeySize = 256 / 8;
        private const int Iterations = 10000;

        public string HashPassword(string password)
        {
            using (var rng = RandomNumberGenerator.Create())
            {
                var salt = new byte[SaltSize];
                rng.GetBytes(salt);

                var hash = KeyDerivation.Pbkdf2(
                    password: password,
                    salt: salt,
                    prf: KeyDerivationPrf.HMACSHA256,
                    iterationCount: Iterations,
                    numBytesRequested: KeySize
                );

                var hashBytes = new byte[SaltSize + KeySize];
                Array.Copy(salt, 0, hashBytes, 0, SaltSize);
                Array.Copy(hash, 0, hashBytes, SaltSize, KeySize);

                return Convert.ToBase64String(hashBytes);
            }
        }

        public bool VerifyPassword(string password, string hashedPassword)
        {
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

        public void ValidatePasswordStrength(string password)
        {
            if (string.IsNullOrWhiteSpace(password))
                throw new ValidationException("Password cannot be empty");

            if (password.Length < 12)
                throw new ValidationException("Password must be at least 12 characters long");

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