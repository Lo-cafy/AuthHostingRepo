using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using Dapper;
using AuthService.Domain.Entities;
using AuthService.Infrastructure.Data.Interfaces;
using AuthService.Infrastructure.Interfaces;
using Newtonsoft.Json;

namespace AuthService.Infrastructure.Repositories
{
    public class RoleRepository : BaseRepository, IRoleRepository
    {
        public RoleRepository(IDbConnectionFactory connectionFactory)
            : base(connectionFactory)
        {
        }

        public async Task<IEnumerable<Role>> GetAllAsync()
        {
            const string sql = @"
            SELECT 
                role_id as RoleId,
                role_name as RoleName,
                role_type as RoleType,
                description as Description,
                permissions as PermissionsJson,
                is_system_role as IsSystemRole,
                is_active as IsActive,
                created_at as CreatedAt
            FROM auth.roles 
            WHERE is_active = true
            ORDER BY role_name";

            var roles = await QueryAsync<Role>(sql);
            foreach (var role in roles)
            {
                if (!string.IsNullOrEmpty(role.PermissionsJson))
                {
                    role.Permissions = JsonConvert.DeserializeObject<List<string>>(role.PermissionsJson);
                }
            }
            return roles;
        }

        public async Task<Role> GetByIdAsync(Guid roleId)
        {
            const string sql = @"
            SELECT 
                role_id as RoleId,
                role_name as RoleName,
                role_type as RoleType,
                description as Description,
                permissions as PermissionsJson,
                is_system_role as IsSystemRole,
                is_active as IsActive,
                created_at as CreatedAt
            FROM auth.roles 
            WHERE role_id = @RoleId";

            var role = await ExecuteAsync<Role>(sql, new { RoleId = roleId });
            if (role != null && !string.IsNullOrEmpty(role.PermissionsJson))
            {
                role.Permissions = JsonConvert.DeserializeObject<List<string>>(role.PermissionsJson);
            }
            return role;
        }

        public async Task<Role> GetByNameAsync(string roleName)
        {
            const string sql = @"
            SELECT 
                role_id as RoleId,
                role_name as RoleName,
                role_type as RoleType,
                description as Description,
                permissions as PermissionsJson,
                is_system_role as IsSystemRole,
                is_active as IsActive,
                created_at as CreatedAt
            FROM auth.roles 
            WHERE role_name = @RoleName AND is_active = true";

            var role = await ExecuteAsync<Role>(sql, new { RoleName = roleName });
            if (role != null && !string.IsNullOrEmpty(role.PermissionsJson))
            {
                role.Permissions = JsonConvert.DeserializeObject<List<string>>(role.PermissionsJson);
            }
            return role;
        }

        public async Task AssignRoleAsync(UserRole userRole)
        {
            const string sql = @"
            INSERT INTO auth.user_roles (
                user_id, role_id, assigned_by, assigned_at, expires_at, is_active
            ) VALUES (
                @UserId, @RoleId, @AssignedBy, CURRENT_TIMESTAMP, @ExpiresAt, true
            ) ON CONFLICT (user_id, role_id) 
            DO UPDATE SET 
                is_active = true,
                assigned_at = CURRENT_TIMESTAMP,
                assigned_by = @AssignedBy,
                expires_at = @ExpiresAt";

            await ExecuteCommandAsync(sql, userRole);
        }

        public async Task RemoveRoleAsync(Guid userId, Guid roleId)
        {
            const string sql = @"
            UPDATE auth.user_roles 
            SET is_active = false
            WHERE user_id = @UserId AND role_id = @RoleId";

            await ExecuteCommandAsync(sql, new { UserId = userId, RoleId = roleId });
        }

        public async Task<IEnumerable<UserRole>> GetUserRolesAsync(Guid userId)
        {
            const string sql = @"
            SELECT 
                ur.user_id as UserId,
                ur.role_id as RoleId,
                ur.assigned_by as AssignedBy,
                ur.assigned_at as AssignedAt,
                ur.expires_at as ExpiresAt,
                ur.is_active as IsActive,
                r.role_name as RoleName,
                r.role_type as RoleType,
                r.description as Description,
                r.permissions as PermissionsJson,
                r.is_system_role as IsSystemRole
            FROM auth.user_roles ur
            INNER JOIN auth.roles r ON r.role_id = ur.role_id
            WHERE ur.user_id = @UserId 
            AND ur.is_active = true 
            AND r.is_active = true
            AND (ur.expires_at IS NULL OR ur.expires_at > CURRENT_TIMESTAMP)";

            var userRoles = await QueryAsync<UserRole>(sql, new { UserId = userId });
            foreach (var userRole in userRoles)
            {
                if (!string.IsNullOrEmpty(userRole.Role?.PermissionsJson))
                {
                    userRole.Role.Permissions = JsonConvert.DeserializeObject<List<string>>(userRole.Role.PermissionsJson);
                }
            }
            return userRoles;
        }
    }
}