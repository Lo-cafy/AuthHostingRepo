using System.Data;
using Microsoft.Extensions.Configuration;
using Npgsql;
using AuthService.Infrastructure.Data.Interfaces;

namespace AuthService.Infrastructure.Data
{
    public class DbConnectionFactory : IDbConnectionFactory
    {
        private readonly string _connectionString;

        public DbConnectionFactory(IConfiguration configuration)
        {
            _connectionString = configuration.GetConnectionString("AuthDb")
                ?? throw new InvalidOperationException("Connection string 'AuthDb' not found.");
        }

        public IDbConnection CreateConnection()
        {
            var connection = new NpgsqlConnection(_connectionString);
            connection.Open();
            return connection;
        }

        public async Task<IDbConnection> CreateConnectionAsync()
        {
            var connection = new NpgsqlConnection(_connectionString);
            await connection.OpenAsync();
            return connection;
        }
    }
}