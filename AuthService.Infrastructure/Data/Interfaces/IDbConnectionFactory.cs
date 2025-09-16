using Npgsql;
using System.Data;

namespace AuthService.Infrastructure.Data.Interfaces
{
    public interface IDbConnectionFactory
    {
       
        NpgsqlConnection CreateConnection();
        Task<IDbConnection> CreateConnectionAsync();
    }
}