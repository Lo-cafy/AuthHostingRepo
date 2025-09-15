using System.Text.Json;

namespace AuthService.Infrastructure.Interfaces
{
    public interface IDatabaseFunctionService
    {
        Task<JsonDocument> RegisterWithPasswordAsync(
            Guid userId,
            string email,
            string password,
            string role = "customer",
            string ipAddress = null,
            string userAgent = null,
            Guid? requestId = null);

        Task<JsonDocument> AuthenticatePasswordAsync(
            string email,
            string password,
            object deviceInfo = null,
            Guid? requestId = null);

        Task<JsonDocument> VerifyEmailAsync(
            string token,
            Guid? requestId = null);

        Task<JsonDocument> RefreshJwtTokenAsync(
            string refreshJti,
            object deviceInfo = null,
            Guid? requestId = null);

        Task<JsonDocument> LogoutSessionAsync(
            string jti,
            string reason = "user_logout",
            Guid? requestId = null);
    }
}