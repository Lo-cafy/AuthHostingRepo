using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using AuthService.Domain.Entities;

namespace AuthService.Infrastructure.Data.Configurations
{
    public class UserCredentialConfiguration : IEntityTypeConfiguration<UserCredential>
    {
        public void Configure(EntityTypeBuilder<UserCredential> builder)
        {
            builder.ToTable("user_credentials");

            builder.HasKey(x => x.CredentialId);

            builder.Property(x => x.CredentialId)
                .HasColumnName("credential_id")
                .HasDefaultValueSql("nextval('auth.seq_credentials')");

            builder.Property(x => x.UserId)
                .HasColumnName("user_id")
                .IsRequired();

            builder.Property(x => x.Email)
                .HasColumnName("email")
                .HasMaxLength(100)
                .IsRequired();

            builder.HasIndex(x => x.Email)
                .IsUnique();

            builder.Property(x => x.PasswordHash)
                .HasColumnName("password_hash")
                .HasMaxLength(255)
                .IsRequired();

            builder.Property(x => x.FailedAttempts)
                .HasColumnName("failed_attempts")
                .HasDefaultValue(0);

            builder.Property(x => x.LockedUntil)
                .HasColumnName("locked_until");

            builder.Property(x => x.Role)
                .HasColumnName("role")
                .HasConversion<string>()
                .HasDefaultValue("customer");
        }
    }
}