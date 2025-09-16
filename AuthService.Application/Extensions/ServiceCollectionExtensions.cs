using AuthService.Application.Interfaces;
using AuthService.Application.Services;
using AuthService.Infrastructure.Data;
using AuthService.Infrastructure.Data.Interfaces;
using AuthService.Infrastructure.Interfaces;
using AuthService.Infrastructure.Repositories;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace AuthService.Application.Extensions
{
    public static class ServiceCollectionExtensions
    {

        public static IServiceCollection AddApplicationServices(this IServiceCollection services, IConfiguration configuration)

        {
            services.AddScoped<IAuthService, AuthService.Application.Services.AuthService>();
            services.Configure<DatabaseOptions>(configuration.GetSection(DatabaseOptions.SectionName));
            services.AddSingleton<IDbConnectionFactory, NpgsqlConnectionFactory>();

            
            services.AddScoped<IUserCredentialRepository, UserCredentialRepository>();
            services.AddScoped<IJwtSessionRepository, JwtSessionRepository>();
            services.AddScoped<ILoginAttemptRepository, LoginAttemptRepository>();

            
            services.AddScoped<IJwtService, JwtService>();
            services.AddScoped<IPasswordService, PasswordService>();
            services.AddScoped<IDigitalFingerprintService, DigitalFingerprintService>();
            return services;
        }
    }
}
