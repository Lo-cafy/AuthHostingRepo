using System;
using System.Threading.Tasks;
using Grpc.Core;
using AuthService.Application.Interfaces;
using AuthService.Application.DTOs.Auth;
using AuthService.Application.DTOs.Common;


namespace AuthService.Grpc.Services
{
    public class OAuthGrpcService : OAuthService.OAuthServiceBase
    {
        private readonly IOAuthService _oAuthService;
        private readonly ILogger<OAuthGrpcService> _logger;

        public OAuthGrpcService(IOAuthService oAuthService, ILogger<OAuthGrpcService> logger)
        {
            _oAuthService = oAuthService;
            _logger = logger;
        }

        public override async Task<AuthResponse> AuthenticateGoogle(GoogleAuthRequest request, ServerCallContext context)
        {
            try
            {
                var dto = new GoogleAuthRequestDto
                {
                    IdToken = request.IdToken,
                    AccessToken = request.AccessToken,
                    DeviceInfo = request.DeviceInfo != null ? new DeviceInfoDto
                    {
                        IpAddress = request.DeviceInfo.IpAddress,
                        UserAgent = request.DeviceInfo.UserAgent
                    } : null
                };

                var result = await _oAuthService.AuthenticateGoogleAsync(dto);

                return new AuthResponse
                {
                    Success = result.Success,
                    UserId = result.UserId.ToString(),
                    AccessToken = result.AccessToken,
                    RefreshToken = result.RefreshToken,
                    ExpiresIn = result.ExpiresIn,
                    TokenType = result.TokenType,
                    IsNewUser = result.IsNewUser
                };
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Google authentication failed");
                return new AuthResponse
                {
                    Success = false,
                    Error = "GOOGLE_AUTH_FAILED",
                    Message = ex.Message
                };
            }
        }

        public override async Task<AuthResponse> AuthenticateFacebook(FacebookAuthRequest request, ServerCallContext context)
        {
            try
            {
                var dto = new FacebookAuthRequestDto
                {
                    AccessToken = request.AccessToken,
                    DeviceInfo = request.DeviceInfo != null ? new DeviceInfoDto
                    {
                        IpAddress = request.DeviceInfo.IpAddress,
                        UserAgent = request.DeviceInfo.UserAgent
                    } : null
                };

                var result = await _oAuthService.AuthenticateFacebookAsync(dto);

                return new AuthResponse
                {
                    Success = result.Success,
                    UserId = result.UserId.ToString(),
                    AccessToken = result.AccessToken,
                    RefreshToken = result.RefreshToken,
                    ExpiresIn = result.ExpiresIn,
                    TokenType = result.TokenType,
                    IsNewUser = result.IsNewUser
                };
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Facebook authentication failed");
                return new AuthResponse
                {
                    Success = false,
                    Error = "FACEBOOK_AUTH_FAILED",
                    Message = ex.Message
                };
            }
        }

        public override async Task<LinkOAuthResponse> LinkOAuthAccount(LinkOAuthRequest request, ServerCallContext context)
        {
            try
            {
                var userId = int.Parse(request.UserId);
                var success = await _oAuthService.LinkOAuthAccountAsync(userId, request.Provider, request.AccessToken);

                return new LinkOAuthResponse
                {
                    Success = success,
                    Message = success ? $"{request.Provider} account linked successfully" : "Failed to link account"
                };
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to link OAuth account");
                return new LinkOAuthResponse
                {
                    Success = false,
                    Message = ex.Message
                };
            }
        }

        public override async Task<GetLinkedAccountsResponse> GetLinkedAccounts(GetLinkedAccountsRequest request, ServerCallContext context)
        {
            try
            {
                var userId = int.Parse(request.UserId);
                var accounts = await _oAuthService.GetLinkedAccountsAsync(userId);

                var response = new GetLinkedAccountsResponse();
                foreach (var account in accounts)
                {
                    response.Accounts.Add(new LinkedAccount
                    {
                        Provider = account.Provider,
                        ProviderEmail = account.ProviderEmail,
                        IsPrimary = account.IsPrimary,
                        ConnectedAt = Google.Protobuf.WellKnownTypes.Timestamp.FromDateTime(account.ConnectedAt.ToUniversalTime()),
                        LastUsedAt = account.LastUsedAt.HasValue
                            ? Google.Protobuf.WellKnownTypes.Timestamp.FromDateTime(account.LastUsedAt.Value.ToUniversalTime())
                            : null
                    });
                }

                return response;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to get linked accounts");
                throw new RpcException(new Status(StatusCode.Internal, ex.Message));
            }
        }
    }
}