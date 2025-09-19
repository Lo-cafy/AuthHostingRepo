//using Microsoft.EntityFrameworkCore;
//using AuthService.Domain.Entities;
//using System.Reflection;

//namespace AuthService.Infrastructure.Data
//{
//    public class AuthDbContext : DbContext
//    {
//        public AuthDbContext(DbContextOptions<AuthDbContext> options) : base(options) { }

//        public DbSet<UserCredential> UserCredentials { get; set; }
//        public DbSet<OAuthProvider> OAuthProviders { get; set; }
//        public DbSet<OAuthConnection> OAuthConnections { get; set; }
//        public DbSet<JwtSession> JwtSessions { get; set; }
//        public DbSet<LoginAttempt> LoginAttempts { get; set; }
//        public DbSet<SecurityToken> SecurityTokens { get; set; }
//        public DbSet<Role> Roles { get; set; }
//        public DbSet<UserRole> UserRoles { get; set; }
//        public DbSet<DeviceFingerprint> DeviceFingerprints { get; set; }

//        protected override void OnModelCreating(ModelBuilder modelBuilder)
//        {
//            modelBuilder.HasDefaultSchema("auth");

//            // Configure sequences
//            modelBuilder.HasSequence<int>("seq_credentials", "auth")
//                .StartsAt(1000)
//                .IncrementsBy(1);

//            modelBuilder.HasSequence<int>("seq_sessions", "auth")
//                .StartsAt(1)
//                .IncrementsBy(1);

//            // Device Fingerprints
//            modelBuilder.Entity<DeviceFingerprint>(entity =>
//            {
//                entity.ToTable("device_fingerprints");
//                entity.HasKey(e => e.FingerprintId);
//                entity.Property(e => e.FingerprintId).HasColumnName("fingerprint_id");
//                entity.Property(e => e.UserId).HasColumnName("user_id").IsRequired();
//                entity.Property(e => e.DeviceId).HasColumnName("device_id").HasMaxLength(255);
//                entity.Property(e => e.DeviceName).HasColumnName("device_name").HasMaxLength(100);
//                entity.Property(e => e.DeviceType).HasColumnName("device_type").HasMaxLength(50);
//                entity.Property(e => e.FingerprintHash).HasColumnName("fingerprint_hash").HasMaxLength(255);
//                entity.Property(e => e.CreatedAt).HasColumnName("created_at");
//                entity.Property(e => e.LastUsedAt).HasColumnName("last_used_at");
//            });

//            // JWT Sessions
//            modelBuilder.Entity<JwtSession>(entity =>
//            {
//                entity.ToTable("jwt_sessions");
//                entity.HasKey(e => e.SessionId);
//                entity.Property(e => e.SessionId).HasColumnName("session_id");
//                entity.Property(e => e.UserId).HasColumnName("user_id").IsRequired();
//                entity.Property(e => e.Jti).HasColumnName("jti").HasMaxLength(255);
//                entity.Property(e => e.RefreshJti).HasColumnName("refresh_jti").HasMaxLength(255);
//                entity.Property(e => e.IsActive).HasColumnName("is_active");
//            });

//            // Login Attempts
//            modelBuilder.Entity<LoginAttempt>(entity =>
//            {
//                entity.ToTable("login_attempts");
//                entity.HasKey(e => e.AttemptId);
//                entity.Property(e => e.AttemptId).HasColumnName("attempt_id");
//                entity.Property(e => e.Identifier).HasColumnName("identifier").HasMaxLength(100);
//                entity.Property(e => e.Success).HasColumnName("success");
//                entity.Property(e => e.AttemptedAt).HasColumnName("attempted_at");
//            });

//            // OAuth Providers
//            modelBuilder.Entity<OAuthProvider>(entity =>
//            {
//                entity.ToTable("oauth_providers");
//                entity.HasKey(e => e.ProviderId);
//                entity.Property(e => e.ProviderId).HasColumnName("provider_id");
//                entity.Property(e => e.ProviderName).HasColumnName("provider_name").HasMaxLength(50);
//                entity.Property(e => e.ClientId).HasColumnName("client_id").HasMaxLength(100);
//                entity.Property(e => e.IsActive).HasColumnName("is_active");
//            });

//            // OAuth Connections
//            modelBuilder.Entity<OAuthConnection>(entity =>
//            {
//                entity.ToTable("oauth_connections");
//                entity.HasKey(e => e.ConnectionId);
//                entity.Property(e => e.ConnectionId).HasColumnName("connection_id");
//                entity.Property(e => e.UserId).HasColumnName("user_id").IsRequired();
//                entity.Property(e => e.ProviderId).HasColumnName("provider_id").IsRequired();
//                entity.HasOne(e => e.Provider)
//                    .WithMany()
//                    .HasForeignKey(e => e.ProviderId);
//            });

//            // Roles
//            modelBuilder.Entity<Role>(entity =>
//            {
//                entity.ToTable("roles");
//                entity.HasKey(e => e.RoleId);
//                entity.Property(e => e.RoleId).HasColumnName("role_id");
//                entity.Property(e => e.RoleName).HasColumnName("role_name").HasMaxLength(50);
//                entity.Property(e => e.Description).HasColumnName("description").HasMaxLength(100);
//            });

//            // User Roles
//            modelBuilder.Entity<UserRole>(entity =>
//            {
//                entity.ToTable("user_roles");
//                entity.HasKey(e => e.AssignmentId);
//                entity.Property(e => e.AssignmentId).HasColumnName("assignment_id");
//                entity.Property(e => e.UserId).HasColumnName("user_id").IsRequired();
//                entity.Property(e => e.RoleId).HasColumnName("role_id").IsRequired();
//                entity.HasOne(e => e.Role)
//                    .WithMany()
//                    .HasForeignKey(e => e.RoleId);
//            });

//            // Apply any additional configurations from separate configuration classes
//            modelBuilder.ApplyConfigurationsFromAssembly(Assembly.GetExecutingAssembly());
//        }
//    }
//}