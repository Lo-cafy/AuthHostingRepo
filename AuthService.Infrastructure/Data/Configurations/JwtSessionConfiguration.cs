using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using AuthService.Domain.Entities;

namespace AuthService.Infrastructure.Data.Configurations
{
    public class JwtSessionConfiguration : IEntityTypeConfiguration<JwtSession>
    {
        public void Configure(EntityTypeBuilder<JwtSession> builder)
        {
            builder.ToTable("jwt_sessions");

            builder.HasKey(x => x.SessionId);

            builder.Property(x => x.SessionId)
                .HasColumnName("session_id");

            builder.Property(x => x.UserId)
                .HasColumnName("user_id")
                .IsRequired();

            builder.Property(x => x.Jti)
                .HasColumnName("jti")
                .HasMaxLength(255)
                .IsRequired();

            builder.HasIndex(x => x.Jti)
                .IsUnique();

            builder.Property(x => x.RefreshJti)
                .HasColumnName("refresh_jti")
                .HasMaxLength(255)
                .IsRequired();

            builder.HasIndex(x => x.RefreshJti)
                .IsUnique();

            builder.Property(x => x.IpAddress)
                .HasColumnName("ip_address");

            builder.Property(x => x.UserAgent)
                .HasColumnName("user_agent");

            builder.Property(x => x.Location)
                .HasColumnName("location");

            builder.Property(x => x.CreatedAt)
                .HasColumnName("created_at");

            builder.Property(x => x.LastAccessedAt)
                .HasColumnName("last_accessed_at");

            builder.Property(x => x.ExpiresAt)
                .HasColumnName("expires_at")
                .IsRequired();

            builder.Property(x => x.IsActive)
                .HasColumnName("is_active")
                .HasDefaultValue(true);

            builder.Property(x => x.RevokedAt)
                .HasColumnName("revoked_at");

            builder.Property(x => x.RevokeReason)
                .HasColumnName("revoke_reason")
                .HasMaxLength(100);
        }
    }
}