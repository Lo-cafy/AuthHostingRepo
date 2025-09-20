using System.Threading.Tasks;
using AuthService.Application.DTOs.Auth;
using AuthService.Application.DTOs.Auth.OAuth;

namespace AuthService.Application.Interfaces
{
    public interface IOAuthService
    {
        Task<string> GetAuthorizationUrlAsync(string provider);
        Task<OAuthCallbackDto> HandleCallbackAsync(string provider, string code, string state);
        Task<AuthResultDto> AuthenticateGoogleAsync(GoogleAuthRequestDto request);
        Task<AuthResultDto> AuthenticateFacebookAsync(FacebookAuthRequestDto request);
        Task<bool> LinkOAuthAccountAsync(int userId, string provider, string accessToken);
        Task<IEnumerable<LinkedAccountDto>> GetLinkedAccountsAsync(int userId);
    }
}