using System.Threading.Tasks;
using AuthService.Application.DTOs.Account;

namespace AuthService.Application.Interfaces
{
    public interface IAccountService
    {
        Task<bool> VerifyEmailAsync(VerifyEmailDto request);
        Task<bool> RequestPasswordResetAsync(string email);
        Task<bool> ResetPasswordAsync(ResetPasswordDto request);
        Task<bool> ChangePasswordAsync(ChangePasswordDto request);
    }
}