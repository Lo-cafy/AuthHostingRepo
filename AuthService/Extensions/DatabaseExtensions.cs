using AuthService.Application.Interfaces;
using AuthService.Application.Services;
using AuthService.Infrastructure.Data;
using AuthService.Infrastructure.Data.Interfaces;
using AuthService.Infrastructure.Interfaces;
using AuthService.Infrastructure.Repositories;
using AuthService.Infrastructure.Services;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace AuthService.Api.Extensions
{
    public static class DatabaseExtensions
    {
        public static IServiceCollection AddDatabase(this IServiceCollection services, IConfiguration configuration)
        {
           
            services.Configure<DatabaseOptions>(configuration.GetSection("Database"));
            services.AddSingleton<IDbConnectionFactory, NpgsqlConnectionFactory>();

         
            services.AddScoped<IDatabaseFunctionService, DatabaseFunctionService>();

     
            services.AddScoped<IUserCredentialRepository, UserCredentialRepository>();
            services.AddScoped<IJwtSessionRepository, JwtSessionRepository>();
            services.AddScoped<ILoginAttemptRepository, LoginAttemptRepository>();

            return services;
        }
    }
}