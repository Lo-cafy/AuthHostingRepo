
using Microsoft.Extensions.Options;
using Npgsql;
using AuthService.Infrastructure.Data.Interfaces;

namespace AuthService.Infrastructure.Data
{
    public class NpgsqlConnectionFactory : IDbConnectionFactory
    {
        private readonly DatabaseOptions _options; 

        public NpgsqlConnectionFactory(IOptions<DatabaseOptions> options)
        {
            _options = options.Value;
        }

        public NpgsqlConnection CreateConnection()
        {
            return new NpgsqlConnection(_options.ConnectionString);
        }

        public async Task<NpgsqlConnection> CreateConnectionAsync()
        {
            var connection = new NpgsqlConnection(_options.ConnectionString);
            await connection.OpenAsync();
            return connection;
        }
    }
}
