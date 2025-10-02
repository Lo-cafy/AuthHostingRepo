using System;
using System.Text.Json;
using System.Threading.Tasks;

namespace AuthService.Infrastructure.Interfaces
{
    public interface IDatabaseFunctionService
    {
        Task<JsonDocument> RegisterWithPasswordAsync(int userId, string email, string password, string role = "customer", string ipAddress = null, string userAgent = null, Guid? requestId = null);

        Task<JsonDocument> AuthenticatePasswordAsync(string email, string password, object deviceInfo = null, Guid? requestId = null);
        Task<JsonDocument> RefreshJwtTokenAsync(string refreshJti, object deviceInfo = null, Guid? requestId = null);

        Task<JsonDocument> LogoutSessionAsync(string jti, string reason = "user_logout", Guid? requestId = null);
    }
}