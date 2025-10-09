using Grpc.Core;
using AuthService.Application.Interfaces;
using AuthService.Grpc.Protos;
using AuthService.Application.DTOs.Auth;
using Microsoft.Extensions.Logging;

namespace AuthService.Grpc.Services
{
    public class AuthGrpcService : Protos.AuthService.AuthServiceBase
    {
        private readonly IAuthService _authService;
        private readonly IAccountService _accountService;
        private readonly ILogger<AuthGrpcService> _logger;

        public AuthGrpcService(IAuthService authService, IAccountService accountService, ILogger<AuthGrpcService> logger)
        {
            _authService = authService;
            _accountService = accountService;
            _logger = logger;
        }

        public override async Task<RegisterUserResponse> RegisterUser(RegisterUserRequest request, ServerCallContext context)
        {
            try
            {
                var registerDto = new RegisterRequestDto
                {
                    Email = request.Email,
                    Password = request.Password,
                };

                var result = await _accountService.RegisterAsync(registerDto);

                return new RegisterUserResponse
                {
                    Success = result.Success,
                    Message = result.Message
                };
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error during user registration");
                return new RegisterUserResponse
                {
                    Success = false,
                    Message = "Internal server error"
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