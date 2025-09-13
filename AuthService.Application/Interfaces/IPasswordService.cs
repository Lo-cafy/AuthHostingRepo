namespace AuthService.Application.Interfaces
{
    public interface IPasswordService
    {
        string HashPassword(string password);
        bool VerifyPassword(string password, string hashedPassword);
        void ValidatePasswordStrength(string password);
    }
}