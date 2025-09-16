using System.Threading.Tasks;
using AuthService.Application.DTOs.Auth;

namespace AuthService.Application.Interfaces
{
    public interface IAuthService
    {
        Task<LoginResponseDto> LoginAsync(LoginRequestDto request);
        Task<RegisterResponseDto> RegisterAsync(RegisterRequestDto request);
        Task<RefreshTokenResponseDto> RefreshTokenAsync(RefreshTokenRequestDto request);
        Task<AuthResultDto> AuthenticateAsync(string email, string password);
        Task<bool> ValidateTokenAsync(string token);
        Task LogoutAsync(string jti);
    }
}