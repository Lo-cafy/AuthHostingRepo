using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using AuthService.Application.Interfaces;
using AuthService.Application.DTOs.Role;
using AuthService.Infrastructure.Interfaces;
using AuthService.Domain.Entities;

namespace AuthService.Application.Services
{
    public class RoleService : IRoleService
    {
        private readonly IRoleRepository _roleRepository;
        private readonly ILogger<RoleService> _logger;

        public RoleService(IRoleRepository roleRepository, ILogger<RoleService> logger)
        {
            _roleRepository = roleRepository;
            _logger = logger;
        }

        public async Task<IEnumerable<RoleDto>> GetRolesAsync()
        {
            var roles = await _roleRepository.GetAllAsync();
            return roles.Select(r => new RoleDto
            {
                RoleId = r.RoleId,
                RoleName = r.RoleName,
                RoleType = r.RoleType,
                Description = r.Description
            });
        }

        public async Task<bool> AssignRoleAsync(AssignRoleDto request)
        {
            try
            {
                var role = await _roleRepository.GetByIdAsync(request.RoleId);
                if (role == null)
                {
                    throw new Exception("Role not found");
                }

                var userRole = new UserRole
                {
                    AssignmentId = new int(),
                    UserId = request.UserId,
                    RoleId = request.RoleId,
                    AssignedBy = request.AssignedBy,
                    AssignedAt = DateTime.UtcNow,
                    ExpiresAt = request.ExpiresAt,
                    IsActive = true
                };

                await _roleRepository.AssignRoleAsync(userRole);
                return true;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to assign role");
                throw;
            }
        }

        public async Task<bool> RemoveRoleAsync(int userId, int roleId)
        {
            try
            {
                await _roleRepository.RemoveRoleAsync(userId, roleId);
                return true;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to remove role");
                throw;
            }
        }

        public async Task<IEnumerable<UserRoleDto>> GetUserRolesAsync(int userId)
        {
            var userRoles = await _roleRepository.GetUserRolesAsync(userId);
            return userRoles.Select(ur => new UserRoleDto
            {
                UserId = ur.UserId,
                RoleId = ur.RoleId,
                RoleName = ur.Role.RoleName,
                AssignedAt = ur.AssignedAt,
                ExpiresAt = ur.ExpiresAt,
                IsActive = ur.IsActive
            });
        }
    }
}