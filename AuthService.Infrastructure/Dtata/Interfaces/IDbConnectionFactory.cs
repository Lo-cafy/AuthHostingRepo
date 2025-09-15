using System.Data;
using System.Threading.Tasks;

namespace AuthService.Infrastructure.Data.Interfaces
{
    public interface IDbConnectionFactory
    {
        IDbConnection CreateConnection();
        Task<IDbConnection> CreateConnectionAsync();
    }
}