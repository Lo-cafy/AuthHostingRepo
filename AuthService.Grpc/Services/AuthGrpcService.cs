using Grpc.Core;
using AuthService.Application.Interfaces;
using AuthService.Grpc.Protos;
using static AuthService.Grpc.Protos.AuthService;
using AuthService.Application.DTOs.Auth;
using Microsoft.Extensions.Logging;
using Newtonsoft.Json;

namespace AuthService.Grpc.Services
{
    public class AuthGrpcService : AuthServiceBase
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
                    UserId = int.Parse(request.UserId),
                    Email = request.Email,
                    Password = request.Password,
                    PhoneNumber = request.PhoneNumber,
                    ReferredBy = null, 
                    ClientIp = string.IsNullOrEmpty(request.ClientIp) ? null : request.ClientIp

                };

                var result = await _accountService.RegisterGrpcAsync(registerDto);

                return new RegisterUserResponse
                {
                    Success = result.Success,
                    Message = result.Message,
                    UserId = result.UserId.ToString(),
                    CredentialId = result.CredentialId.ToString()   
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

        public override async Task<ValidateTokenResponse> ValidateToken(
            Protos.ValidateTokenRequest request, ServerCallContext context)
        {
            try
            {
                var isValid = await _authService.ValidateTokenAsync(request.Token);

                return new ValidateTokenResponse
                {
                    Valid = isValid,
                    Error = isValid ? string.Empty : "Invalid token"
                };
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error during token validation");
                return new ValidateTokenResponse
                {
                    Valid = false,
                    Error = "Internal server error"
                };
            }
        }
    }
}