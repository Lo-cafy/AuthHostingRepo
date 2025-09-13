namespace AuthService.Application.Interfaces
{
    public interface ISecurityService
    {
        Task<bool> ValidateSecurityToken(string token);
    }
}