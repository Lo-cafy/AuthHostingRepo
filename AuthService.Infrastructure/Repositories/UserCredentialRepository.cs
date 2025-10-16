using AuthService.Domain.Entities;
using AuthService.Infrastructure.Data.Interfaces;
using AuthService.Infrastructure.Interfaces;
using Dapper;
using System.Data;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace AuthService.Infrastructure.Repositories
{
    public class UserCredentialRepository : IUserCredentialRepository
    {
        private readonly IDbConnectionFactory _connectionFactory;

        public UserCredentialRepository(IDbConnectionFactory connectionFactory)
        {
            _connectionFactory = connectionFactory;
        }

        public async Task<UserCredential?> GetByEmailAsync(string email)
        {
            using var connection = await _connectionFactory.CreateConnectionAsync();

            var sql = @"
                SELECT 
                    credential_id AS CredentialId,
                    user_id AS UserId,
                    email AS Email,
                    password_hash AS PasswordHash,
                    password_salt AS PasswordSalt,
                    role AS Role,
                    is_active AS IsActive,
                    failed_attempts AS FailedAttempts,
                    locked_until AS LockedUntil,
                    password_changed_at AS PasswordChangedAt,
                    created_at AS CreatedAt,
                    updated_at AS UpdatedAt
                FROM auth.user_credentials
                WHERE email = @Email AND is_active = true";

            return await connection.QueryFirstOrDefaultAsync<UserCredential>(sql, new { Email = email });
        }

        public async Task<UserCredential?> GetByUserIdAsync(int userId)
        {
            using var connection = await _connectionFactory.CreateConnectionAsync();

            var sql = @"
                SELECT 
                    credential_id AS CredentialId,
                    user_id AS UserId,
                    email AS Email,
                    password_hash AS PasswordHash,
                    password_salt AS PasswordSalt,
                    role AS Role,
                    is_active AS IsActive,
                    failed_attempts AS FailedAttempts,
                    locked_until AS LockedUntil,
                    password_changed_at AS PasswordChangedAt,
                    created_at AS CreatedAt,
                    updated_at AS UpdatedAt
                FROM auth.user_credentials
                WHERE user_id = @UserId AND is_active = true";

            return await connection.QueryFirstOrDefaultAsync<UserCredential>(sql, new { UserId = userId });
        }
        public async Task<UserCredential> CreateAsync(UserCredential credential)
        {
            using var connection = await _connectionFactory.CreateConnectionAsync();

            var sql = @"
                INSERT INTO auth.user_credentials (
                    user_id,
                    email,
                    password_hash,
                    password_salt,
                    password_algorithm,
                    password_iterations,
                    password_memory,
                    password_parallelism,
                    role,
                    created_at,
                    updated_at,
                    is_active
                 ) VALUES (
                    @UserId,
                    @Email,
                    @PasswordHash,
                    @PasswordSalt,
                    'argon2id',
                    3,
                    65536,
                    1,
                    @Role::auth.role_type_enum,
                    CURRENT_TIMESTAMP,
                    CURRENT_TIMESTAMP,
                    true
                ) RETURNING credential_id";
                
                
            var credentialId = await connection.ExecuteScalarAsync<int>(sql, credential);
            credential.CredentialId = credentialId;

            return credential;
        }

        public async Task<(int UserId, int CredentialId)> RegisterUserEnhancedAsync( int userId, string email,string passwordHash, string passwordSalt,
                                                                                      string role,string? phoneNumber, int? referredBy, string createdIp)
        {
            using var connection = await _connectionFactory.CreateConnectionAsync();

            var sql = @"
                    SELECT * FROM auth.register_user_enhanced(
                       p_user_id        => @UserId,
               p_email          => @Email,
               p_password_hash  => @PasswordHash,
               p_password_salt  => @PasswordSalt,
               p_role           => @Role,
               p_phone_number   => @PhoneNumber,
               p_referred_by    => @ReferredBy,
               p_created_ip     => @CreatedIp::inet
                        );
                           ";

            var parameters = new
            {
                UserId = userId,
                Email = email,
                PasswordHash = passwordHash,
                PasswordSalt = passwordSalt,
                Role = role,
                PhoneNumber = phoneNumber,
                ReferredBy = referredBy,
                CreatedIp = createdIp // string like "192.168.1.1"
            };

            var result = await connection.QueryFirstAsync<(int UserId, int CredentialId)>(sql, parameters);
            return result;
        }

        public async Task<LoginResult?> AuthenticateUserAsync(string email, string password)
        {
            using var connection = await _connectionFactory.CreateConnectionAsync();

            var sql = "SELECT auth.authenticate_user_secure(@Email, @Password)::jsonb";

            var parameters = new
            {
                Email = email.ToLower(),
                Password = password
            };

            // Get result as string
            var result = await connection.QueryFirstOrDefaultAsync<string>(sql, parameters);

            if (string.IsNullOrEmpty(result))
            {
                return null;
            }

            var options = new JsonSerializerOptions { PropertyNameCaseInsensitive = true };

            return JsonSerializer.Deserialize<LoginResult>(result, options);
        }




        public async Task UpdateAsync(UserCredential credential)
        {
            using var connection = await _connectionFactory.CreateConnectionAsync();

            var sql = @"
            UPDATE auth.user_credentials 
            SET 
                password_hash = @PasswordHash,
                password_salt = @PasswordSalt,
                role = @Role,
                is_active = @IsActive,
                failed_attempts = @FailedAttempts,
                locked_until = @LockedUntil,
                password_changed_at = CASE 
                    WHEN @PasswordHash != password_hash 
                    THEN CURRENT_TIMESTAMP 
                    ELSE password_changed_at 
                END,
                updated_at = CURRENT_TIMESTAMP
            WHERE credential_id = @CredentialId";

            await connection.ExecuteAsync(sql, credential);
        }

        public async Task<bool> EmailExistsAsync(string email)
        {
            using var connection = await _connectionFactory.CreateConnectionAsync();

            var sql = @"
            SELECT EXISTS(
                SELECT 1 
                FROM auth.user_credentials 
                WHERE email = @Email 
                AND is_active = true
            )";

            return await connection.ExecuteScalarAsync<bool>(sql, new { Email = email });
        }
    }
}