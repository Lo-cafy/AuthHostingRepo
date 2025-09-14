using AuthService.Application.Interfaces;
using AuthService.Application.Services;
using AuthService.Infrastructure.Data;
using AuthService.Infrastructure.Data.Interfaces;
using AuthService.Infrastructure.Interfaces;
using AuthService.Infrastructure.Repositories;
using AuthService.Shared;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace AuthService.Infrastructure.Extensions
{
    public static class ServiceExtensions
    {
        public static IServiceCollection AddInfrastructureServices(this IServiceCollection services, IConfiguration configuration)
        {
            // Configure Database
            services.Configure<DatabaseOptions>(configuration.GetSection(DatabaseOptions.SectionName));
            services.AddSingleton<IDbConnectionFactory, NpgsqlConnectionFactory>();

            // Register Repositories
            services.AddScoped<IOAuthRepository, OAuthRepository>();
            services.AddScoped<IDeviceFingerprintRepository, DeviceFingerprintRepository>();
            services.AddScoped<IUserRepository, UserRepository>();

            return services;
        }

        public static IServiceCollection AddApplicationServices(this IServiceCollection services)
        {
            // Register Application Services
            services.AddScoped<IOAuthService, OAuthService>();
            services.AddScoped<IDeviceFingerprintService, DeviceFingerprintService>();
            services.AddScoped<IJwtService, JwtService>();
            services.AddScoped<ISecurityService, SecurityService>();

            return services;
        }
    }
}