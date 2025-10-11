//
// ✅ THIS IS THE FIX
//
using Npgsql;
using AuthService.Infrastructure.Data.Interfaces;
using System.Data; // Required for the IDbConnection interface

namespace AuthService.Infrastructure.Data
{
    public class NpgsqlConnectionFactory : IDbConnectionFactory
    {
        private readonly NpgsqlDataSource _dataSource;

        // It MUST take the pre-configured NpgsqlDataSource in its constructor
        public NpgsqlConnectionFactory(NpgsqlDataSource dataSource)
        {
            _dataSource = dataSource;
        }

        public async Task<IDbConnection> CreateConnectionAsync()
        {
            // This connection already knows about your enum mapping!
            return await _dataSource.OpenConnectionAsync();
        }
    }
}