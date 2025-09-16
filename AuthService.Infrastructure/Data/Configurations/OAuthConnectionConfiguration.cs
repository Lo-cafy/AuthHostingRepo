using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using AuthService.Domain.Entities;

namespace AuthService.Infrastructure.Data.Configurations
{
    public class OAuthConnectionConfiguration : IEntityTypeConfiguration<OAuthConnection>
    {
        public void Configure(EntityTypeBuilder<OAuthConnection> builder)
        {
            builder.ToTable("oauth_connections");

            builder.HasKey(x => x.ConnectionId);

            builder.Property(x => x.ConnectionId)
                .HasColumnName("connection_id");

            builder.Property(x => x.UserId)
                .HasColumnName("user_id")
                .IsRequired();

            builder.Property(x => x.ProviderId)
                .HasColumnName("provider_id")
                .IsRequired();

            builder.Property(x => x.ProviderUserId)
                .HasColumnName("provider_user_id")
                .HasMaxLength(155)
                .IsRequired();

            builder.Property(x => x.ProviderEmail)
                .HasColumnName("provider_email")
                .HasMaxLength(100);

            builder.Property(x => x.ProviderData)
                .HasColumnName("provider_data");

            builder.Property(x => x.AccessTokenEncrypted)
                .HasColumnName("access_token_encrypted")
                .HasMaxLength(800);

            builder.Property(x => x.RefreshTokenEncrypted)
                .HasColumnName("refresh_token_encrypted")
                .HasMaxLength(800);

            builder.Property(x => x.TokenExpiresAt)
                .HasColumnName("token_expires_at");

            builder.Property(x => x.IsPrimary)
                .HasColumnName("is_primary")
                .HasDefaultValue(false);

            builder.Property(x => x.ConnectedAt)
                .HasColumnName("connected_at");

            builder.Property(x => x.LastUsedAt)
                .HasColumnName("last_used_at");

            builder.HasIndex(x => new { x.ProviderId, x.ProviderUserId })
                .IsUnique();

            builder.HasIndex(x => new { x.UserId, x.ProviderId })
                .IsUnique();

            builder.HasOne(x => x.Provider)
                .WithMany()
                .HasForeignKey(x => x.ProviderId);
        }
    }
}