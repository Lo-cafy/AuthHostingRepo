namespace AuthService.Application.Interfaces
{
    public interface IPasswordService
    {
        string HashPassword(string password);
        string HashPasswordWithSalt(string password, string salt);
        bool VerifyPassword(string password, string hashedPassword);
        bool VerifyPasswordWithSalt(string password, string hashedPassword, string salt);
        void ValidatePasswordStrength(string password);
    }
}