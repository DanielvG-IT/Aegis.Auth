using Aegis.Auth.Entities;

using Microsoft.EntityFrameworkCore;

namespace Aegis.Auth.Extensions
{
    public static class ModelBuilderExtensions
    {
        public static ModelBuilder ApplyAegisAuthModel(this ModelBuilder modelBuilder)
        {
            ArgumentNullException.ThrowIfNull(modelBuilder);

            modelBuilder.Entity<User>(entity =>
            {
                entity.HasKey(e => e.Id);
                entity.HasIndex(e => e.Email).IsUnique();
                entity.Property(e => e.Email).IsRequired();
            });

            modelBuilder.Entity<Account>(entity =>
            {
                entity.HasKey(e => e.Id);
                entity.HasIndex(e => e.UserId);
                entity.HasIndex(e => e.ProviderId);
                entity.HasIndex(e => new { e.ProviderId, e.AccountId }).IsUnique();
                entity.HasIndex(e => new { e.UserId, e.ProviderId });
                entity.HasOne(e => e.User)
                    .WithMany(u => u.Accounts)
                    .HasForeignKey(e => e.UserId)
                    .OnDelete(DeleteBehavior.Cascade);
            });

            modelBuilder.Entity<Session>(entity =>
            {
                entity.HasKey(e => e.Id);
                entity.HasIndex(e => e.TokenHash).IsUnique();
                entity.HasIndex(e => e.UserId);
                entity.HasIndex(e => e.ExpiresAt);
                entity.HasOne(e => e.User)
                    .WithMany(u => u.Sessions)
                    .HasForeignKey(e => e.UserId)
                    .OnDelete(DeleteBehavior.Cascade);
            });

            modelBuilder.Entity<AuthToken>(entity =>
            {
                entity.HasKey(e => e.Id);
                entity.HasIndex(e => new { e.UserId, e.Purpose, e.TokenHash }).IsUnique();
                entity.HasIndex(e => e.ExpiresAt);
                entity.HasIndex(e => e.ConsumedAt);
                entity.HasOne(e => e.User)
                    .WithMany(u => u.AuthTokens)
                    .HasForeignKey(e => e.UserId)
                    .OnDelete(DeleteBehavior.Cascade);
            });

            return modelBuilder;
        }
    }
}
