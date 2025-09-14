using System.Data;
using Dapper;
using AuthService.Infrastructure.Data.Interfaces;

namespace AuthService.Infrastructure.Repositories
{
    public abstract class BaseRepository
    {
        protected readonly IDbConnectionFactory _connectionFactory;

        protected BaseRepository(IDbConnectionFactory connectionFactory)
        {
            _connectionFactory = connectionFactory;
        }

        protected async Task<T> ExecuteAsync<T>(string sql, object? parameters = null)
        {
            using var connection = await _connectionFactory.CreateConnectionAsync();
            return await connection.QuerySingleOrDefaultAsync<T>(sql, parameters);
        }

        protected async Task<IEnumerable<T>> QueryAsync<T>(string sql, object? parameters = null)
        {
            using var connection = await _connectionFactory.CreateConnectionAsync();
            return await connection.QueryAsync<T>(sql, parameters);
        }

        protected async Task<int> ExecuteCommandAsync(string sql, object? parameters = null)
        {
            using var connection = await _connectionFactory.CreateConnectionAsync();
            return await connection.ExecuteAsync(sql, parameters);
        }

        protected async Task<T> ExecuteScalarAsync<T>(string sql, object? parameters = null)
        {
            using var connection = await _connectionFactory.CreateConnectionAsync();
            return await connection.ExecuteScalarAsync<T>(sql, parameters);
        }
    }
}