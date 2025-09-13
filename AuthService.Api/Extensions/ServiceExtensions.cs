using AuthService.Application.Interfaces;
using AuthService.Application.Services;
using AuthService.Infrastructure.Interfaces;
using AuthService.Infrastructure.Repositories;

namespace AuthService.Api.Extensions
{
    public static class ServiceExtensions
    {
        public static IServiceCollection AddApplicationServices(this IServiceCollection services)
        {
            // Application Services
            services.AddScoped<IAuthService, AuthService.Application.Services.AuthService>();
            services.AddScoped<IJwtService, JwtService>();
            services.AddScoped<IPasswordService, PasswordService>();
            services.AddScoped<IOAuthService, OAuthService>();
            services.AddScoped<IDigitalFingerprintService, DigitalFingerprintService>();
            services.AddScoped<IAccountService, AccountService>();
            services.AddScoped<IRoleService, RoleService>();
            services.AddScoped<ISecurityTokenService, SecurityTokenService>();

            return services;
        }

        public static IServiceCollection AddInfrastructureServices(this IServiceCollection services)
        {
            // Repositories
            services.AddScoped<IUserCredentialRepository, UserCredentialRepository>();
            services.AddScoped<IOAuthRepository, OAuthRepository>();
            services.AddScoped<IJwtSessionRepository, JwtSessionRepository>();
            services.AddScoped<ILoginAttemptRepository, LoginAttemptRepository>();
            services.AddScoped<ISecurityTokenRepository, SecurityTokenRepository>();
            services.AddScoped<IRoleRepository, RoleRepository>();

            return services;
        }
    }
}