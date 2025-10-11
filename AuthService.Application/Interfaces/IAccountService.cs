using System.Threading.Tasks;
using AuthService.Application.DTOs.Account;
using AuthService.Application.DTOs.Auth;

namespace AuthService.Application.Interfaces
{
    public interface IAccountService
    {
       
        Task<bool> RequestPasswordResetAsync(string email);
        Task<bool> ResetPasswordAsync(ResetPasswordDto request);
        Task<bool> ChangePasswordAsync(ChangePasswordDto request);
        Task<RegisterResponseDto> RegisterAsync(RegisterRequestDto request);
        Task<RegisterResponseDto> RegisterGrpcAsync(RegisterRequestDto request);

    }
}