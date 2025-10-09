using System.Threading.Tasks;

namespace UserService.Application.Interface
{
    public interface IEmailNotificationService
    {
        Task<bool> SendVerificationEmailAsync(string email, string userName,string verificationLink);
      

    }
}
