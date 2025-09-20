using Microsoft.Extensions.Configuration; // <-- Add this using statement
using Npgsql;
using AuthService.Infrastructure.Data.Interfaces;

namespace AuthService.Infrastructure.Data
{
    public class NpgsqlConnectionFactory : IDbConnectionFactory
    {
        private readonly string _connectionString;

        // Inject IConfiguration instead of IOptions
        public NpgsqlConnectionFactory(IConfiguration configuration)
        {
            // Get the connection string from the "ConnectionStrings" section
            _connectionString = configuration.GetConnectionString("AuthDb");
        }

        public NpgsqlConnection CreateConnection()
        {
            // Use the connection string retrieved from IConfiguration
            return new NpgsqlConnection(_connectionString);
        }

        public async Task<NpgsqlConnection> CreateConnectionAsync()
        {
            var connection = new NpgsqlConnection(_connectionString);
            await connection.OpenAsync();
            return connection;
        }
    }
}
