using System.Threading.Tasks;
using AuthService.Domain.Entities;

namespace AuthService.Infrastructure.Interfaces
{
    public interface ILoginAttemptRepository
    {
        Task<int> GetRecentFailuresAsync(string fingerprint, int minutes);
        Task CreateAsync(LoginAttempt attempt);
    }
}