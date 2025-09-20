using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using AuthService.Domain.Entities;

namespace AuthService.Infrastructure.Interfaces
{
    public interface IRoleRepository
    {
        Task<IEnumerable<Role>> GetAllAsync();
        Task<Role> GetByIdAsync(int roleId);
        Task<Role> GetByNameAsync(string roleName);
        Task AssignRoleAsync(UserRole userRole);
        Task RemoveRoleAsync(int userId, int roleId);
        Task<IEnumerable<UserRole>> GetUserRolesAsync(int userId);
    }
}