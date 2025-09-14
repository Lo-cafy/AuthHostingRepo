using AuthService.Domain.Entities;
using AuthService.Infrastructure.Data.Interfaces;
using AuthService.Infrastructure.Interfaces;
using Dapper;

namespace AuthService.Infrastructure.Repositories
{
    public class UserCredentialRepository : BaseRepository, IUserCredentialRepository
    {
        public UserCredentialRepository(IDbConnectionFactory connectionFactory)
            : base(connectionFactory)
        {
        }

        public async Task<UserCredential> GetByEmailAsync(string email)
        {
            const string sql = @"
                SELECT 
                    credential_id as CredentialId,
                    user_id as UserId,
                    email as Email,
                    password_hash as PasswordHash,
                    password_salt as PasswordSalt,
                    role as Role,
                    is_active as IsActive,
                    failed_attempts as FailedAttempts,
                    locked_until as LockedUntil,
                    password_changed_at as PasswordChangedAt,
                    created_at as CreatedAt,
                    updated_at as UpdatedAt
                FROM auth.user_credentials 
                WHERE email = @Email AND is_active = true";

            return await ExecuteAsync<UserCredential>(sql, new { Email = email });
        }

        public async Task<UserCredential> GetByUserIdAsync(Guid userId)
        {
            const string sql = @"
                SELECT 
                    credential_id as CredentialId,
                    user_id as UserId,
                    email as Email,
                    password_hash as PasswordHash,
                    password_salt as PasswordSalt,
                    role as Role,
                    is_active as IsActive,
                    failed_attempts as FailedAttempts,
                    locked_until as LockedUntil,
                    password_changed_at as PasswordChangedAt,
                    created_at as CreatedAt,
                    updated_at as UpdatedAt
                FROM auth.user_credentials 
                WHERE user_id = @UserId AND is_active = true";

            return await ExecuteAsync<UserCredential>(sql, new { UserId = userId });
        }

        public async Task<bool> EmailExistsAsync(string email)
        {
            const string sql = @"
                SELECT COUNT(1) 
                FROM auth.user_credentials 
                WHERE email = @Email AND is_active = true";

            var count = await ExecuteScalarAsync<int>(sql, new { Email = email });
            return count > 0;
        }

        public async Task<UserCredential> CreateAsync(UserCredential credential)
        {
            const string sql = @"
                INSERT INTO auth.user_credentials 
                (
                    user_id, 
                    email, 
                    password_hash, 
                    password_salt, 
                    role, 
                    is_active, 
                    failed_attempts,
                    locked_until,
                    password_changed_at,
                    created_at, 
                    updated_at
                )
                VALUES 
                (
                    @UserId, 
                    @Email, 
                    @PasswordHash, 
                    @PasswordSalt, 
                    @Role, 
                    @IsActive, 
                    @FailedAttempts,
                    @LockedUntil,
                    @PasswordChangedAt,
                    @CreatedAt, 
                    @UpdatedAt
                )
                RETURNING credential_id as CredentialId";

            var credentialId = await ExecuteScalarAsync<long>(sql, credential);
            credential.CredentialId = credentialId;
            return credential;
        }

        public async Task UpdateAsync(UserCredential credential)
        {
            const string sql = @"
                UPDATE auth.user_credentials 
                SET 
                    password_hash = @PasswordHash,
                    password_salt = @PasswordSalt,
                    role = @Role,
                    is_active = @IsActive,
                    failed_attempts = @FailedAttempts,
                    locked_until = @LockedUntil,
                    password_changed_at = @PasswordChangedAt,
                    updated_at = @UpdatedAt
                WHERE credential_id = @CredentialId";

            await ExecuteCommandAsync(sql, credential);
        }

        public async Task UpdateLoginAttemptsAsync(long credentialId, int failedAttempts, DateTime? lockedUntil)
        {
            const string sql = @"
                UPDATE auth.user_credentials 
                SET 
                    failed_attempts = @FailedAttempts,
                    locked_until = @LockedUntil,
                    updated_at = CURRENT_TIMESTAMP
                WHERE credential_id = @CredentialId";

            await ExecuteCommandAsync(sql, new
            {
                CredentialId = credentialId,
                FailedAttempts = failedAttempts,
                LockedUntil = lockedUntil
            });
        }

        public async Task ResetLoginAttemptsAsync(long credentialId)
        {
            const string sql = @"
                UPDATE auth.user_credentials 
                SET 
                    failed_attempts = 0,
                    locked_until = NULL,
                    updated_at = CURRENT_TIMESTAMP
                WHERE credential_id = @CredentialId";

            await ExecuteCommandAsync(sql, new { CredentialId = credentialId });
        }
    }
}