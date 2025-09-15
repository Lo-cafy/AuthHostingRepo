using System;
using System.Threading.Tasks;
using Dapper;
using AuthService.Domain.Entities;
using AuthService.Infrastructure.Data.Interfaces;
using AuthService.Infrastructure.Interfaces;
using Newtonsoft.Json;

namespace AuthService.Infrastructure.Repositories
{
    public class UserCredentialRepository : BaseRepository, IUserCredentialRepository
    {
        public UserCredentialRepository(IDbConnectionFactory connectionFactory)
            : base(connectionFactory)
        {
        }

        public async Task<dynamic> RegisterWithPasswordAsync(
            Guid userId,
            string email,
            string password,
            string roleName = "customer",
            string ipAddress = null,
            string userAgent = null,
            Guid? requestId = null)
        {
            var parameters = new DynamicParameters();
            parameters.Add("p_user_id", userId);
            parameters.Add("p_email", email);
            parameters.Add("p_password", password);
            parameters.Add("p_role_name", roleName);
            parameters.Add("p_ip_address", ipAddress);
            parameters.Add("p_user_agent", userAgent);
            parameters.Add("p_request_id", requestId);

            var result = await ExecuteAsync<string>(
                "SELECT auth.register_with_password(@p_user_id, @p_email, @p_password, @p_role_name, @p_ip_address::inet, @p_user_agent, @p_request_id)",
                parameters);

            return JsonConvert.DeserializeObject<dynamic>(result);
        }

        public async Task<dynamic> AuthenticatePasswordAsync(
            string email,
            string password,
            object deviceInfo = null,
            Guid? requestId = null)
        {
            var parameters = new DynamicParameters();
            parameters.Add("p_email", email);
            parameters.Add("p_password", password);
            parameters.Add("p_device_info", JsonConvert.SerializeObject(deviceInfo ?? new { }));
            parameters.Add("p_request_id", requestId);

            var result = await ExecuteAsync<string>(
                "SELECT auth.authenticate_password(@p_email, @p_password, @p_device_info::jsonb, @p_request_id)",
                parameters);

            return JsonConvert.DeserializeObject<dynamic>(result);
        }
        public async Task<bool> UpdateAsync(UserCredential credential)
        {
            const string sql = @"
            UPDATE auth.user_credentials 
            SET password_hash = @PasswordHash,
                password_salt = @PasswordSalt,
                failed_attempts = @FailedAttempts,
                locked_until = @LockedUntil,
                password_changed_at = @PasswordChangedAt,
                must_change_password = @MustChangePassword,
                role = @Role,
                is_active = @IsActive,
                updated_at = CURRENT_TIMESTAMP
            WHERE user_id = @UserId";

            var parameters = new
            {
                credential.UserId,
                credential.PasswordHash,
                credential.PasswordSalt,
                credential.FailedAttempts,
                credential.LockedUntil,
                credential.PasswordChangedAt,
                credential.MustChangePassword,
                credential.Role,
                credential.IsActive
            };

            var affected = await ExecuteCommandAsync(sql, parameters);
            return affected > 0;
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
                    failed_attempts as FailedAttempts,
                    locked_until as LockedUntil,
                    is_active as IsActive,
                    created_at as CreatedAt,
                    updated_at as UpdatedAt
                FROM auth.user_credentials
                WHERE email = @Email AND is_active = true";

            return await ExecuteAsync<UserCredential>(sql, new { Email = email });
        }
        public async Task<UserCredential> CreateAsync(UserCredential credential)
        {
            const string sql = @"
            INSERT INTO auth.user_credentials (
                user_id, email, password_hash, password_salt,
                password_algorithm, password_iterations, role,
                failed_attempts, must_change_password, is_active
            ) VALUES (
                @UserId, @Email, @PasswordHash, @PasswordSalt,
                @PasswordAlgorithm, @PasswordIterations, @Role,
                @FailedAttempts, @MustChangePassword, @IsActive
            ) RETURNING 
                credential_id as CredentialId,
                created_at as CreatedAt,
                updated_at as UpdatedAt";

            var parameters = new
            {
                credential.UserId,
                credential.Email,
                credential.PasswordHash,
                credential.PasswordSalt,
                PasswordAlgorithm = "bcrypt",
                PasswordIterations = 12,
                credential.Role,
                FailedAttempts = 0,
                MustChangePassword = false,
                IsActive = true
            };

            var result = await ExecuteAsync<UserCredential>(sql, parameters);

            credential.CredentialId = result.CredentialId;
            credential.CreatedAt = result.CreatedAt;
            credential.UpdatedAt = result.UpdatedAt;
            credential.IsActive = true;
            credential.FailedAttempts = 0;

            return credential;
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
                    failed_attempts as FailedAttempts,
                    locked_until as LockedUntil,
                    is_active as IsActive,
                    created_at as CreatedAt,
                    updated_at as UpdatedAt
                FROM auth.user_credentials
                WHERE user_id = @UserId AND is_active = true";

            return await ExecuteAsync<UserCredential>(sql, new { UserId = userId });
        }

        public async Task<bool> UpdateFailedAttemptsAsync(long credentialId, int failedAttempts, DateTime? lockedUntil)
        {
            const string sql = @"
                UPDATE auth.user_credentials 
                SET failed_attempts = @FailedAttempts,
                    locked_until = @LockedUntil,
                    updated_at = CURRENT_TIMESTAMP
                WHERE credential_id = @CredentialId";

            var affected = await ExecuteCommandAsync(sql, new
            {
                CredentialId = credentialId,
                FailedAttempts = failedAttempts,
                LockedUntil = lockedUntil
            });

            return affected > 0;
        }

        public async Task<bool> UpdatePasswordAsync(Guid userId, string newPasswordHash, string newPasswordSalt)
        {
            const string sql = @"
                UPDATE auth.user_credentials 
                SET password_hash = @PasswordHash,
                    password_salt = @PasswordSalt,
                    password_changed_at = CURRENT_TIMESTAMP,
                    updated_at = CURRENT_TIMESTAMP
                WHERE user_id = @UserId";

            var affected = await ExecuteCommandAsync(sql, new
            {
                UserId = userId,
                PasswordHash = newPasswordHash,
                PasswordSalt = newPasswordSalt
            });

            return affected > 0;
        }
    }
}