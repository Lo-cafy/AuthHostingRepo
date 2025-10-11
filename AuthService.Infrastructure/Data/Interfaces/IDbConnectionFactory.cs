// AuthService.Infrastructure/Data/Interfaces/IDbConnectionFactory.cs
using Npgsql;
using System.Data;

namespace AuthService.Infrastructure.Data.Interfaces
{
    public interface IDbConnectionFactory
    {
        Task<IDbConnection> CreateConnectionAsync();

    }
}
