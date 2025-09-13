using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using AuthService.Domain.Entities;

namespace AuthService.Infrastructure.Interfaces
{
    public interface IRoleRepository
    {
        Task<IEnumerable<Role>> GetAllAsync();
        Task<Role> GetByIdAsync(Guid roleId);
        Task<Role> GetByNameAsync(string roleName);
        Task AssignRoleAsync(UserRole userRole);
        Task RemoveRoleAsync(Guid userId, Guid roleId);
        Task<IEnumerable<UserRole>> GetUserRolesAsync(Guid userId);
    }
}