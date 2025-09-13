using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using AuthService.Domain.Entities;

namespace AuthService.Infrastructure.Data.Configurations
{
    public class SecurityTokenConfiguration : IEntityTypeConfiguration<SecurityToken>
    {
        public void Configure(EntityTypeBuilder<SecurityToken> builder)
        {
            builder.ToTable("security_tokens");

            builder.HasKey(x => x.TokenId);

            builder.Property(x => x.TokenId)
                .HasColumnName("token_id");

            builder.Property(x => x.UserId)
                .HasColumnName("user_id")
                .IsRequired();

            builder.Property(x => x.TokenType)
                .HasColumnName("token_type")
                .HasConversion<string>()
                .IsRequired();

            builder.Property(x => x.TokenHash)
                .HasColumnName("token_hash")
                .HasMaxLength(255)
                .IsRequired();

            builder.HasIndex(x => x.TokenHash)
                .IsUnique();

            builder.Property(x => x.ExpiresAt)
                .HasColumnName("expires_at")
                .IsRequired();

            builder.Property(x => x.UsedAt)
                .HasColumnName("used_at");

            builder.Property(x => x.Metadata)
                .HasColumnName("metadata")
                .HasDefaultValue("{}");

            builder.Property(x => x.CreatedAt)
                .HasColumnName("created_at");
        }
    }
}