using Grpc.Core;
using Microsoft.Extensions.Logging;
using AuthService.Application.Interfaces;
using AuthService.Grpc.Protos;

namespace AuthService.Grpc.Services
{
    public class AuthGrpcService : Protos.AuthService.AuthServiceBase
    {
        private readonly IAuthService _authService;
        private readonly ILogger<AuthGrpcService> _logger;

        public AuthGrpcService(IAuthService authService, ILogger<AuthGrpcService> logger)
        {
            _authService = authService;
            _logger = logger;
        }

        public override async Task<Protos.AuthResponse> Authenticate(
            Protos.AuthRequest request, ServerCallContext context)
        {
            try
            {
                var result = await _authService.AuthenticateAsync(request.Email, request.Password);

                return new Protos.AuthResponse
                {
                    Success = result.Success,
                    Token = result.Success ? result.AccessToken : string.Empty,
                    Error = result.Success ? string.Empty : result.Error
                };
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error during authentication");
                return new Protos.AuthResponse
                {
                    Success = false,
                    Error = "Internal server error"
                };
            }
        }

        public override async Task<Protos.ValidateTokenResponse> ValidateToken(
            Protos.ValidateTokenRequest request, ServerCallContext context)
        {
            try
            {
                var isValid = await _authService.ValidateTokenAsync(request.Token);

                return new Protos.ValidateTokenResponse
                {
                    Valid = isValid,
                    Error = isValid ? string.Empty : "Invalid token"
                };
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error during token validation");
                return new Protos.ValidateTokenResponse
                {
                    Valid = false,
                    Error = "Internal server error"
                };
            }
        }
    }
}