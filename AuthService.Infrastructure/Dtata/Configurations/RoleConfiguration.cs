using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using AuthService.Domain.Entities;

namespace AuthService.Infrastructure.Data.Configurations
{
    public class RoleConfiguration : IEntityTypeConfiguration<Role>
    {
        public void Configure(EntityTypeBuilder<Role> builder)
        {
            builder.ToTable("roles");

            builder.HasKey(x => x.RoleId);

            builder.Property(x => x.RoleId)
                .HasColumnName("role_id");

            builder.Property(x => x.RoleName)
                .HasColumnName("role_name")
                .HasMaxLength(50)
                .IsRequired();

            builder.HasIndex(x => x.RoleName)
                .IsUnique();

            builder.Property(x => x.RoleType)
                .HasColumnName("role_type")
                .HasConversion<string>()
                .IsRequired();

            builder.Property(x => x.Description)
                .HasColumnName("description")
                .HasMaxLength(100);

            builder.Property(x => x.IsSystemRole)
                .HasColumnName("is_system_role")
                .HasDefaultValue(false);

            builder.Property(x => x.CreatedAt)
                .HasColumnName("created_at");
        }
    }
}