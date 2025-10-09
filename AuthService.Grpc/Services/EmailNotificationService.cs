using AuthService.Application.DTOs.Auth;
using EmailService.Grpc;
using Microsoft.Extensions.Logging;
using Newtonsoft.Json;
using UserService.Application.Interface;
using static EmailService.Grpc.EmailService;


namespace AuthService.Grpc.Services
{
    public class EmailNotificationService : IEmailNotificationService
    {
        private readonly EmailServiceClient _client;
        private readonly ILogger<EmailNotificationService> _logger;

        public EmailNotificationService(EmailServiceClient client, ILogger<EmailNotificationService> logger)
        {
            _client = client;
            _logger = logger;
        }

        public async Task<bool> SendVerificationEmailAsync(string email, string userName, string verificationLink)
        {
            if (string.IsNullOrWhiteSpace(email))
            {
                _logger.LogError("❌ SendVerificationEmailAsync called with null or empty email!");
                throw new ArgumentException("Email cannot be null or empty.", nameof(email));
            }

            var emailModel = new PasswordResetEmailModel
            {
                UserName = string.IsNullOrEmpty(userName) ? email.Split("@")[0] : userName,
                ResetLink = verificationLink
            };

            
            var request = new SendEmailRequest
            {
                ToEmail = email,
                Subject = "Welcome! Please Verify Your Email",
                ViewName = "VerificationEmail",
                ModelJson = JsonConvert.SerializeObject(emailModel)
            };

            _logger.LogInformation("Sending welcome email to {Email} with model: {Model}", request.ToEmail, request.ModelJson);

            var response = await _client.SendEmailAsync(request);
            return response.Success;
        }
    }
}