using System;
using System.Threading.Tasks;
using AuthService.Application.DTOs.Auth;
using AuthService.Application.DTOs.Common;

namespace AuthService.Application.Interfaces
{
    public interface IAuthService
    {

        Task<LoginResponseDto> LoginAsync(LoginRequestDto request, DeviceInfoDto? deviceInfo = null);

        Task<RegisterResponseDto> RegisterAsync(RegisterRequestDto request);

        Task<RefreshTokenResponseDto> RefreshTokenAsync(RefreshTokenRequestDto request);


        Task<AuthResultDto> AuthenticateAsync(string email, string password);


        Task<bool> ValidateTokenAsync(string token);

        Task<bool> LogoutAsync(string jti);


        Task<bool> RevokeAllSessionsAsync(Guid userId);
    }
}