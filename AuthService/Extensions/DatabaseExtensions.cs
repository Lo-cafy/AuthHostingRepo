using AuthService.Application.Interfaces;
using AuthService.Infrastructure.Data;
using AuthService.Infrastructure.Data.Interfaces;
using AuthService.Infrastructure.Interfaces;
using AuthService.Infrastructure.Repositories;
using AuthService.Infrastructure.Services;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace AuthService.Api.Extensions
{
    public static class DatabaseExtensions
    {
        public static IServiceCollection AddDatabase(this IServiceCollection services, IConfiguration configuration)
        {
            // ✅ Read connection string from appsettings.json
            var connectionString = configuration.GetConnectionString("AuthDb");

            // ✅ Register EF Core DbContext (for Entity Framework repositories or migrations)
            services.AddDbContext<ApplicationDbContext>(options =>
            {
                options.UseNpgsql(connectionString, npgsqlOptions =>
                {
                    npgsqlOptions.CommandTimeout(configuration.GetValue<int>("Database:CommandTimeout"));
                });

                // Enable/disable sensitive data logging based on config
                if (configuration.GetValue<bool>("Database:EnableSensitiveDataLogging"))
                {
                    options.EnableSensitiveDataLogging();
                }
            });

            // ✅ Bind Database options (like CommandTimeout)
            services.Configure<DatabaseOptions>(configuration.GetSection("Database"));
            services.AddSingleton<IDbConnectionFactory, NpgsqlConnectionFactory>();
            services.AddScoped<IDatabaseFunctionService, DatabaseFunctionService>();
            services.AddScoped<IUserCredentialRepository, UserCredentialRepository>();
            services.AddScoped<IJwtSessionRepository, JwtSessionRepository>();
            services.AddScoped<ILoginAttemptRepository, LoginAttemptRepository>();
            services.AddScoped<IRoleRepository, RoleRepository>();
            services.AddScoped<ISecurityTokenRepository, SecurityTokenRepository>();
            //services.AddScoped<ISecurityQuestionRepository, SecurityQuestionRepository>();
            services.AddScoped<IOAuthRepository, OAuthRepository>();

            return services;
        }
    }
}
