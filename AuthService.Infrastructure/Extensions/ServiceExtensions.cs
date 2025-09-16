using Microsoft.Extensions.DependencyInjection;
using AuthService.Infrastructure.Data;
using AuthService.Infrastructure.Data.Interfaces;
using AuthService.Infrastructure.Interfaces;
using AuthService.Infrastructure.Repositories;

namespace AuthService.Infrastructure.Extensions
{
    public static class ServiceCollectionExtensions
    {
        public static IServiceCollection AddInfrastructureServices(this IServiceCollection services)
        {
           
            services.AddSingleton<IDbConnectionFactory, NpgsqlConnectionFactory>();

           
            services.AddScoped<IUserCredentialRepository, UserCredentialRepository>();
            services.AddScoped<IOAuthRepository, OAuthRepository>();
            services.AddScoped<IRoleRepository, RoleRepository>();
            services.AddScoped<IJwtSessionRepository, JwtSessionRepository>();
            services.AddScoped<ISecurityTokenRepository, SecurityTokenRepository>();
            services.AddScoped<ILoginAttemptRepository, LoginAttemptRepository>();
            services.AddScoped<IDeviceFingerprintRepository, DeviceFingerprintRepository>();

            return services;
        }
    }
}