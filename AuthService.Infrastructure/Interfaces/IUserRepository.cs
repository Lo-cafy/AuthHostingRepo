namespace AuthService.Infrastructure.Interfaces
{
    public interface IUserRepository
    {
        Task<bool> Exists(string userId);
    }
}