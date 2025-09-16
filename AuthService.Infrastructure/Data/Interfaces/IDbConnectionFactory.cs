// AuthService.Infrastructure/Data/Interfaces/IDbConnectionFactory.cs
using Npgsql;

namespace AuthService.Infrastructure.Data.Interfaces
{
    public interface IDbConnectionFactory
    {
        NpgsqlConnection CreateConnection();
        Task<NpgsqlConnection> CreateConnectionAsync();
    }
}
