using System;
using System.Net.Http;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using Newtonsoft.Json;
using AuthService.Application.Interfaces;
using AuthService.Application.DTOs.Auth;
using AuthService.Application.DTOs.Auth.OAuth;
using AuthService.Infrastructure.Interfaces;
using AuthService.Domain.Entities;
using System.Collections.Generic;
using System.Text;

namespace AuthService.Application.Services
{
    public class OAuthService : IOAuthService
    {
        private readonly IOAuthRepository _oauthRepository;
        private readonly IUserCredentialRepository _credentialRepository;
        private readonly IJwtService _jwtService;
        private readonly IHttpClientFactory _httpClientFactory;
        private readonly ILogger<OAuthService> _logger;

        public OAuthService(
            IOAuthRepository oauthRepository,
            IUserCredentialRepository credentialRepository,
            IJwtService jwtService,
            IHttpClientFactory httpClientFactory,
            ILogger<OAuthService> logger)
        {
            _oauthRepository = oauthRepository;
            _credentialRepository = credentialRepository;
            _jwtService = jwtService;
            _httpClientFactory = httpClientFactory;
            _logger = logger;
        }

        public async Task<AuthResultDto> AuthenticateGoogleAsync(GoogleAuthRequestDto request)
        {
            try
            {
                var userInfo = await VerifyGoogleTokenAsync(request.IdToken, request.AccessToken);
                return await ProcessOAuthAuthenticationAsync("google", userInfo);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Google authentication failed");
                return new AuthResultDto
                {
                    Success = false,
                    Error = "GOOGLE_AUTH_FAILED",
                    Message = ex.Message
                };
            }
        }

        public async Task<AuthResultDto> AuthenticateFacebookAsync(FacebookAuthRequestDto request)
        {
            try
            {
                var userInfo = await VerifyFacebookTokenAsync(request.AccessToken);
                return await ProcessOAuthAuthenticationAsync("facebook", userInfo);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Facebook authentication failed");
                return new AuthResultDto
                {
                    Success = false,
                    Error = "FACEBOOK_AUTH_FAILED",
                    Message = ex.Message
                };
            }
        }

        public async Task<bool> LinkOAuthAccountAsync(Guid userId, string provider, string accessToken)
        {
            try
            {
                var oauthProvider = await _oauthRepository.GetProviderAsync(provider);
                if (oauthProvider == null || !oauthProvider.IsActive)
                {
                    throw new Exception($"OAuth provider {provider} not found or inactive");
                }

                var userInfo = provider.ToLower() switch
                {
                    "google" => await VerifyGoogleTokenAsync(null, accessToken),
                    "facebook" => await VerifyFacebookTokenAsync(accessToken),
                    _ => throw new Exception($"Unsupported provider: {provider}")
                };

                var existingConnection = await _oauthRepository.GetConnectionAsync(
                    oauthProvider.ProviderId, userInfo.Id);

                if (existingConnection != null)
                {
                    throw new Exception("This provider account is already linked to a user");
                }

                var providerData = new Dictionary<string, object>
                {
                    { "name", userInfo.Name },
                    { "email", userInfo.Email },
                    { "picture", userInfo.Picture },
                    { "id", userInfo.Id }
                };

                var connection = new OAuthConnection
                {
                    UserId = userId,
                    ProviderId = oauthProvider.ProviderId,
                    ProviderUserId = userInfo.Id,
                    ProviderEmail = userInfo.Email,
                    ProviderData = providerData,
                    AccessTokenEncrypted = EncryptToken(accessToken),
                    TokenExpiresAt = DateTime.UtcNow.AddHours(1),
                    IsPrimary = false,
                    ConnectedAt = DateTime.UtcNow,
                    LastUsedAt = DateTime.UtcNow,
                    IsActive = true
                };

                await _oauthRepository.CreateConnectionAsync(connection);
                return true;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to link OAuth account");
                return false;
            }
        }

        public async Task<IEnumerable<LinkedAccountDto>> GetLinkedAccountsAsync(Guid userId)
        {
            try
            {
                var connections = await _oauthRepository.GetUserConnectionsAsync(userId);
                return connections.Select(c => new LinkedAccountDto
                {
                    Provider = c.Provider.ProviderName,
                    ProviderEmail = c.ProviderEmail,
                    IsPrimary = c.IsPrimary,
                    ConnectedAt = c.ConnectedAt,
                    LastUsedAt = c.LastUsedAt
                });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to get linked accounts");
                throw;
            }
        }

        private async Task<OAuthUserInfo> VerifyGoogleTokenAsync(string idToken, string accessToken)
        {
            var client = _httpClientFactory.CreateClient();

            if (!string.IsNullOrEmpty(idToken))
            {
                var response = await client.GetAsync(
                    $"https://oauth2.googleapis.com/tokeninfo?id_token={idToken}");

                if (!response.IsSuccessStatusCode)
                {
                    throw new Exception("Invalid Google ID token");
                }

                var tokenInfo = await response.Content.ReadAsStringAsync();
                return JsonConvert.DeserializeObject<OAuthUserInfo>(tokenInfo);
            }

            client.DefaultRequestHeaders.Authorization =
                new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", accessToken);

            var userInfoResponse = await client.GetAsync(
                "https://www.googleapis.com/oauth2/v2/userinfo");

            if (!userInfoResponse.IsSuccessStatusCode)
            {
                throw new Exception("Failed to get Google user info");
            }

            return JsonConvert.DeserializeObject<OAuthUserInfo>(
                await userInfoResponse.Content.ReadAsStringAsync());
        }

        private async Task<OAuthUserInfo> VerifyFacebookTokenAsync(string accessToken)
        {
            var client = _httpClientFactory.CreateClient();
            var response = await client.GetAsync(
                $"https://graph.facebook.com/me?fields=id,email,name,picture&access_token={accessToken}");

            if (!response.IsSuccessStatusCode)
            {
                throw new Exception("Invalid Facebook access token");
            }

            var content = await response.Content.ReadAsStringAsync();
            return JsonConvert.DeserializeObject<OAuthUserInfo>(content);
        }

        private async Task<AuthResultDto> ProcessOAuthAuthenticationAsync(
            string provider, OAuthUserInfo userInfo)
        {
            var oauthProvider = await _oauthRepository.GetProviderAsync(provider);
            if (oauthProvider == null)
            {
                throw new Exception($"OAuth provider {provider} not found");
            }

            var connection = await _oauthRepository.GetConnectionAsync(
                oauthProvider.ProviderId, userInfo.Id);

            Guid userId;
            bool isNewUser = false;

            if (connection == null)
            {
                var existingUser = await _credentialRepository.GetByEmailAsync(userInfo.Email);

                if (existingUser != null)
                {
                    userId = existingUser.UserId;
                }
                else
                {
                    userId = Guid.NewGuid();
                    isNewUser = true;

                    var credential = new UserCredential
                    {
                        UserId = userId,
                        Email = userInfo.Email,
                        PasswordHash = "OAUTH_USER",
                        Role = "customer",
                        IsActive = true,
                        CreatedAt = DateTime.UtcNow,
                        UpdatedAt = DateTime.UtcNow
                    };

                    await _credentialRepository.CreateAsync(credential);
                }

                var providerData = new Dictionary<string, object>
                {
                    { "name", userInfo.Name },
                    { "email", userInfo.Email },
                    { "picture", userInfo.Picture },
                    { "id", userInfo.Id }
                };

                connection = new OAuthConnection
                {
                    UserId = userId,
                    ProviderId = oauthProvider.ProviderId,
                    ProviderUserId = userInfo.Id,
                    ProviderEmail = userInfo.Email,
                    ProviderData = providerData,
                    IsPrimary = isNewUser,
                    ConnectedAt = DateTime.UtcNow,
                    LastUsedAt = DateTime.UtcNow,
                    IsActive = true
                };

                await _oauthRepository.CreateConnectionAsync(connection);
            }
            else
            {
                userId = connection.UserId;
                connection.LastUsedAt = DateTime.UtcNow;
                await _oauthRepository.UpdateConnectionAsync(connection);
            }

            var jti = Guid.NewGuid().ToString();
            var refreshJti = Guid.NewGuid().ToString();

            var accessToken = _jwtService.GenerateAccessToken(
                userId, userInfo.Email, new[] { "customer" }, jti);
            var refreshToken = _jwtService.GenerateRefreshToken(userId, refreshJti);

            return new AuthResultDto
            {
                Success = true,
                UserId = userId,
                AccessToken = accessToken,
                RefreshToken = refreshToken,
                ExpiresIn = 3600,
                TokenType = "Bearer",
                IsNewUser = isNewUser
            };
        }

        public async Task<string> GetAuthorizationUrlAsync(string provider)
        {
            var oauthProvider = await _oauthRepository.GetProviderAsync(provider);
            if (oauthProvider == null || !oauthProvider.IsActive)
            {
                throw new Exception($"OAuth provider {provider} not found or inactive");
            }

            var state = Guid.NewGuid().ToString();
            var redirectUri = GetRedirectUri(provider);

            var authUrl = $"{oauthProvider.AuthorizationUrl}?" +
                $"client_id={oauthProvider.ClientId}&" +
                $"redirect_uri={Uri.EscapeDataString(redirectUri)}&" +
                $"response_type=code&" +
                $"scope={Uri.EscapeDataString(string.Join(" ", oauthProvider.Scopes))}&" +
                $"state={state}";

            return authUrl;
        }

        public async Task<OAuthCallbackDto> HandleCallbackAsync(
            string provider, string code, string state)
        {
            try
            {
                var oauthProvider = await _oauthRepository.GetProviderAsync(provider);
                if (oauthProvider == null)
                {
                    throw new Exception($"OAuth provider {provider} not found");
                }

                var tokens = await ExchangeCodeForTokensAsync(oauthProvider, code);
                var userInfo = await GetUserInfoAsync(oauthProvider, tokens.AccessToken);

                var connection = await _oauthRepository.GetConnectionAsync(
                    oauthProvider.ProviderId, userInfo.Id);

                Guid userId;
                string email = userInfo.Email;
                bool isNewUser = false;

                if (connection == null)
                {
                    var existingUser = await _credentialRepository.GetByEmailAsync(email);

                    if (existingUser != null)
                    {
                        userId = existingUser.UserId;
                    }
                    else
                    {
                        userId = Guid.NewGuid();
                        isNewUser = true;

                        var credential = new UserCredential
                        {
                            UserId = userId,
                            Email = email,
                            PasswordHash = "OAUTH_USER",
                            Role = "customer",
                            IsActive = true,
                            CreatedAt = DateTime.UtcNow,
                            UpdatedAt = DateTime.UtcNow
                        };

                        await _credentialRepository.CreateAsync(credential);
                    }

                    var providerData = new Dictionary<string, object>
                    {
                        { "name", userInfo.Name },
                        { "email", userInfo.Email },
                        { "picture", userInfo.Picture },
                        { "id", userInfo.Id }
                    };

                    connection = new OAuthConnection
                    {
                        UserId = userId,
                        ProviderId = oauthProvider.ProviderId,
                        ProviderUserId = userInfo.Id,
                        ProviderEmail = email,
                        ProviderData = providerData,
                        AccessTokenEncrypted = EncryptToken(tokens.AccessToken),
                        RefreshTokenEncrypted = !string.IsNullOrEmpty(tokens.RefreshToken)
                            ? EncryptToken(tokens.RefreshToken)
                            : null,
                        TokenExpiresAt = DateTime.UtcNow.AddSeconds(tokens.ExpiresIn),
                        IsPrimary = isNewUser,
                        ConnectedAt = DateTime.UtcNow,
                        LastUsedAt = DateTime.UtcNow,
                        IsActive = true
                    };

                    await _oauthRepository.CreateConnectionAsync(connection);
                }
                else
                {
                    userId = connection.UserId;
                    connection.AccessTokenEncrypted = EncryptToken(tokens.AccessToken);
                    connection.RefreshTokenEncrypted = !string.IsNullOrEmpty(tokens.RefreshToken)
                        ? EncryptToken(tokens.RefreshToken)
                        : null;
                    connection.TokenExpiresAt = DateTime.UtcNow.AddSeconds(tokens.ExpiresIn);
                    connection.LastUsedAt = DateTime.UtcNow;
                    await _oauthRepository.UpdateConnectionAsync(connection);
                }

                var jti = Guid.NewGuid().ToString();
                var refreshJti = Guid.NewGuid().ToString();

                var accessToken = _jwtService.GenerateAccessToken(
                    userId, email, new[] { "customer" }, jti);
                var refreshToken = _jwtService.GenerateRefreshToken(userId, refreshJti);

                return new OAuthCallbackDto
                {
                    Success = true,
                    AccessToken = accessToken,
                    RefreshToken = refreshToken,
                    UserId = userId,
                    Email = email,
                    IsNewUser = isNewUser,
                    Provider = provider
                };
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "OAuth callback failed for provider: {Provider}", provider);
                throw;
            }
        }

        private async Task<TokenResponse> ExchangeCodeForTokensAsync(
            OAuthProvider provider, string code)
        {
            var client = _httpClientFactory.CreateClient();
            var redirectUri = GetRedirectUri(provider.ProviderName);

            var content = new FormUrlEncodedContent(new Dictionary<string, string>
            {
                {"grant_type", "authorization_code"},
                {"code", code},
                {"redirect_uri", redirectUri},
                {"client_id", provider.ClientId},
                {"client_secret", DecryptSecret(provider.ClientSecretEncrypted)}
            });

            var response = await client.PostAsync(provider.TokenUrl, content);
            var responseContent = await response.Content.ReadAsStringAsync();

            if (!response.IsSuccessStatusCode)
            {
                throw new Exception($"Failed to exchange code for tokens: {responseContent}");
            }

            return JsonConvert.DeserializeObject<TokenResponse>(responseContent);
        }

        private async Task<OAuthUserInfo> GetUserInfoAsync(OAuthProvider provider, string accessToken)
        {
            var client = _httpClientFactory.CreateClient();
            client.DefaultRequestHeaders.Authorization =
                new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", accessToken);

            var response = await client.GetAsync(provider.UserInfoUrl);
            var responseContent = await response.Content.ReadAsStringAsync();

            if (!response.IsSuccessStatusCode)
            {
                throw new Exception($"Failed to get user info: {responseContent}");
            }

            return JsonConvert.DeserializeObject<OAuthUserInfo>(responseContent);
        }

        private string GetRedirectUri(string provider)
        {
            // This should come from configuration
            return $"https://localhost:5001/api/oauth/{provider}/callback";
        }

        private string EncryptToken(string token)
        {
            // TODO: Implement proper encryption
            // This is just a placeholder - DO NOT use in production
            return Convert.ToBase64String(Encoding.UTF8.GetBytes(token));
        }

        private string DecryptSecret(string encryptedSecret)
        {
            // TODO: Implement proper decryption
            // This is just a placeholder - DO NOT use in production
            return Encoding.UTF8.GetString(Convert.FromBase64String(encryptedSecret));
        }

        private class TokenResponse
        {
            [JsonProperty("access_token")]
            public required string AccessToken { get; set; }

            [JsonProperty("refresh_token")]
            public string? RefreshToken { get; set; }

            [JsonProperty("expires_in")]
            public int ExpiresIn { get; set; }

            [JsonProperty("token_type")]
            public required string TokenType { get; set; }
        }

        private class OAuthUserInfo
        {
            public string Id { get; set; }
            public string Email { get; set; }
            public string Name { get; set; }
            public string Picture { get; set; }
        }
    }
}