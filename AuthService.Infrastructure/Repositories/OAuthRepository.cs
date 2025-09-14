using System;
using System.Collections.Generic;
using System.Data;
using System.Threading.Tasks;
using System.Linq;
using Dapper;
using Newtonsoft.Json;
using AuthService.Domain.Entities;
using AuthService.Infrastructure.Data.Interfaces;
using AuthService.Infrastructure.Interfaces;

namespace AuthService.Infrastructure.Repositories
{
    public class OAuthRepository : BaseRepository, IOAuthRepository
    {
        public OAuthRepository(IDbConnectionFactory connectionFactory)
            : base(connectionFactory)
        {
        }
        public async Task<OAuthConnection> CreateConnectionAsync(OAuthConnection connection)
        {
            const string sql = @"
        INSERT INTO auth.oauth_connections 
        (
            user_id, provider_id, provider_user_id, provider_email, 
            provider_data, access_token_encrypted, refresh_token_encrypted, 
            token_expires_at, is_primary, is_active, connected_at
        )
        VALUES 
        (
            @UserId, @ProviderId, @ProviderUserId, @ProviderEmail, 
            @ProviderData::jsonb, @AccessTokenEncrypted, @RefreshTokenEncrypted, 
            @TokenExpiresAt, @IsPrimary, @IsActive, CURRENT_TIMESTAMP
        )
        RETURNING 
            connection_id as ConnectionId,
            connected_at as ConnectedAt,
            last_used_at as LastUsedAt";

            var parameters = new
            {
                connection.UserId,
                connection.ProviderId,
                connection.ProviderUserId,
                connection.ProviderEmail,
                ProviderData = JsonConvert.SerializeObject(connection.ProviderData ?? new Dictionary<string, object>()),
                connection.AccessTokenEncrypted,
                connection.RefreshTokenEncrypted,
                connection.TokenExpiresAt,
                connection.IsPrimary,
                IsActive = true
            };

            using var dbConnection = await _connectionFactory.CreateConnectionAsync();
            var result = await dbConnection.QuerySingleAsync<OAuthConnection>(sql, parameters);

            // Update the original connection object with the generated values
            connection.ConnectionId = result.ConnectionId;
            connection.ConnectedAt = result.ConnectedAt;
            connection.LastUsedAt = result.LastUsedAt;
            connection.IsActive = true;

            return connection;
        }

        public async Task<OAuthProvider> GetProviderAsync(string provider)
        {
            const string sql = @"
                SELECT 
                    provider_id as ProviderId,
                    provider_name as ProviderName,
                    client_id as ClientId,
                    client_secret_encrypted as ClientSecretEncrypted,
                    authorization_url as AuthorizationUrl,
                    token_url as TokenUrl,
                    user_info_url as UserInfoUrl,
                    scopes as Scopes,
                    is_active as IsActive,
                    created_at as CreatedAt,
                    updated_at as UpdatedAt
                FROM auth.oauth_providers
                WHERE LOWER(provider_name) = LOWER(@Provider) 
                AND is_active = true";

            return await ExecuteAsync<OAuthProvider>(sql, new { Provider = provider });
        }

        public async Task<OAuthConnection> GetConnectionAsync(Guid providerId, string providerUserId)
        {
            const string sql = @"
                SELECT 
                    oc.connection_id as ConnectionId,
                    oc.user_id as UserId,
                    oc.provider_id as ProviderId,
                    oc.provider_user_id as ProviderUserId,
                    oc.provider_email as ProviderEmail,
                    oc.provider_data as ProviderDataJson,
                    oc.access_token_encrypted as AccessTokenEncrypted,
                    oc.refresh_token_encrypted as RefreshTokenEncrypted,
                    oc.token_expires_at as TokenExpiresAt,
                    oc.is_primary as IsPrimary,
                    oc.connected_at as ConnectedAt,
                    oc.last_used_at as LastUsedAt,
                    oc.is_active as IsActive,
                    op.provider_id,
                    op.provider_name as ProviderName,
                    op.client_id as ClientId,
                    op.authorization_url as AuthorizationUrl,
                    op.token_url as TokenUrl,
                    op.user_info_url as UserInfoUrl,
                    op.scopes as Scopes
                FROM auth.oauth_connections oc
                INNER JOIN auth.oauth_providers op ON oc.provider_id = op.provider_id
                WHERE oc.provider_id = @ProviderId 
                AND oc.provider_user_id = @ProviderUserId";

            using var connection = await _connectionFactory.CreateConnectionAsync();

            var result = await connection.QueryAsync<OAuthConnection, OAuthProvider, OAuthConnection>(
                sql,
                (oauthConnection, provider) =>
                {
                    oauthConnection.Provider = provider;
                    if (!string.IsNullOrEmpty(oauthConnection.ProviderDataJson))
                    {
                        oauthConnection.ProviderData = JsonConvert.DeserializeObject<Dictionary<string, object>>(
                            oauthConnection.ProviderDataJson);
                    }
                    return oauthConnection;
                },
                new { ProviderId = providerId, ProviderUserId = providerUserId },
                splitOn: "provider_id"
            );

            return result.FirstOrDefault();
        }

        public async Task<IEnumerable<OAuthConnection>> GetUserConnectionsAsync(Guid userId)
        {
            const string sql = @"
                SELECT 
                    oc.connection_id as ConnectionId,
                    oc.user_id as UserId,
                    oc.provider_id as ProviderId,
                    oc.provider_user_id as ProviderUserId,
                    oc.provider_email as ProviderEmail,
                    oc.provider_data as ProviderDataJson,
                    oc.access_token_encrypted as AccessTokenEncrypted,
                    oc.refresh_token_encrypted as RefreshTokenEncrypted,
                    oc.token_expires_at as TokenExpiresAt,
                    oc.is_primary as IsPrimary,
                    oc.connected_at as ConnectedAt,
                    oc.last_used_at as LastUsedAt,
                    oc.is_active as IsActive,
                    op.provider_id,
                    op.provider_name as ProviderName,
                    op.client_id as ClientId,
                    op.authorization_url as AuthorizationUrl,
                    op.token_url as TokenUrl,
                    op.user_info_url as UserInfoUrl,
                    op.scopes as Scopes
                FROM auth.oauth_connections oc
                INNER JOIN auth.oauth_providers op ON oc.provider_id = op.provider_id
                WHERE oc.user_id = @UserId
                ORDER BY oc.last_used_at DESC NULLS LAST";

            using var connection = await _connectionFactory.CreateConnectionAsync();

            var result = await connection.QueryAsync<OAuthConnection, OAuthProvider, OAuthConnection>(
                sql,
                (oauthConnection, provider) =>
                {
                    oauthConnection.Provider = provider;
                    if (!string.IsNullOrEmpty(oauthConnection.ProviderDataJson))
                    {
                        oauthConnection.ProviderData = JsonConvert.DeserializeObject<Dictionary<string, object>>(
                            oauthConnection.ProviderDataJson);
                    }
                    return oauthConnection;
                },
                new { UserId = userId },
                splitOn: "provider_id"
            );

            return result;
        }

        public async Task UpdateConnectionAsync(OAuthConnection connection)
        {
            const string sql = @"
                UPDATE auth.oauth_connections 
                SET provider_email = @ProviderEmail,
                    provider_data = @ProviderData::jsonb,
                    access_token_encrypted = @AccessTokenEncrypted,
                    refresh_token_encrypted = @RefreshTokenEncrypted,
                    token_expires_at = @TokenExpiresAt,
                    is_primary = @IsPrimary,
                    last_used_at = CURRENT_TIMESTAMP,
                    is_active = @IsActive
                WHERE connection_id = @ConnectionId";

            var parameters = new
            {
                connection.ConnectionId,
                connection.ProviderEmail,
                ProviderData = JsonConvert.SerializeObject(connection.ProviderData ?? new Dictionary<string, object>()),
                connection.AccessTokenEncrypted,
                connection.RefreshTokenEncrypted,
                connection.TokenExpiresAt,
                connection.IsPrimary,
                connection.IsActive
            };

            await ExecuteCommandAsync(sql, parameters);
        }

        public async Task<OAuthConnection> GetConnectionByProviderEmailAsync(string provider, string email)
        {
            const string sql = @"
                SELECT 
                    oc.connection_id as ConnectionId,
                    oc.user_id as UserId,
                    oc.provider_id as ProviderId,
                    oc.provider_user_id as ProviderUserId,
                    oc.provider_email as ProviderEmail,
                    oc.provider_data as ProviderDataJson,
                    oc.access_token_encrypted as AccessTokenEncrypted,
                    oc.refresh_token_encrypted as RefreshTokenEncrypted,
                    oc.token_expires_at as TokenExpiresAt,
                    oc.is_primary as IsPrimary,
                    oc.connected_at as ConnectedAt,
                    oc.last_used_at as LastUsedAt,
                    oc.is_active as IsActive,
                    op.provider_id,
                    op.provider_name as ProviderName,
                    op.client_id as ClientId,
                    op.authorization_url as AuthorizationUrl,
                    op.token_url as TokenUrl,
                    op.user_info_url as UserInfoUrl,
                    op.scopes as Scopes
                FROM auth.oauth_connections oc
                INNER JOIN auth.oauth_providers op ON oc.provider_id = op.provider_id
                WHERE LOWER(op.provider_name) = LOWER(@Provider) 
                AND LOWER(oc.provider_email) = LOWER(@Email)";

            using var connection = await _connectionFactory.CreateConnectionAsync();

            var result = await connection.QueryAsync<OAuthConnection, OAuthProvider, OAuthConnection>(
                sql,
                (oauthConnection, provider) =>
                {
                    oauthConnection.Provider = provider;
                    if (!string.IsNullOrEmpty(oauthConnection.ProviderDataJson))
                    {
                        oauthConnection.ProviderData = JsonConvert.DeserializeObject<Dictionary<string, object>>(
                            oauthConnection.ProviderDataJson);
                    }
                    return oauthConnection;
                },
                new { Provider = provider, Email = email },
                splitOn: "provider_id"
            );

            return result.FirstOrDefault();
        }
    }
}