using System;
using System.Threading.Tasks;
using System.Collections.Generic;
using AuthService.Application.DTOs.Role;

namespace AuthService.Application.Interfaces
{
    public interface IRoleService
    {
        Task<IEnumerable<RoleDto>> GetRolesAsync();
        Task<bool> AssignRoleAsync(AssignRoleDto request);
        Task<bool> RemoveRoleAsync(int userId, int roleId);
        Task<IEnumerable<UserRoleDto>> GetUserRolesAsync(int userId);
    }
}