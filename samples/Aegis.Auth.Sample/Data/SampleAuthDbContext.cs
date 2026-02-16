using Aegis.Auth.Abstractions;
using Aegis.Auth.Entities;

using Microsoft.EntityFrameworkCore;

namespace Aegis.Auth.Sample.Data;

public class SampleAuthDbContext(DbContextOptions<SampleAuthDbContext> options) : DbContext(options), IAuthDbContext
{
    public DbSet<User> Users { get; set; } = null!;
    public DbSet<Account> Accounts { get; set; } = null!;
    public DbSet<Session> Sessions { get; set; } = null!;

    // ═══════════════════════════════════════════════════════════════════════════════
    // EMAIL VERIFICATION - DISABLED FOR v0.1, WILL BE RE-ENABLED IN v0.2
    // ═══════════════════════════════════════════════════════════════════════════════
    // TODO v0.2: Uncomment this for email verification support
    // public DbSet<Verification> Verifications { get; set; } = null!;
    // ═══════════════════════════════════════════════════════════════════════════════

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        base.OnModelCreating(modelBuilder);

        // User configuration
        modelBuilder.Entity<User>(entity =>
        {
            entity.HasKey(e => e.Id);
            entity.HasIndex(e => e.Email).IsUnique();
            entity.Property(e => e.Email).IsRequired();
        });

        // Account configuration
        modelBuilder.Entity<Account>(entity =>
        {
            entity.HasKey(e => e.Id);
            entity.HasIndex(e => e.UserId);
            entity.HasIndex(e => e.ProviderId);
            entity.HasIndex(e => new { e.UserId, e.ProviderId }); // Composite index for credential lookups
            entity.HasOne(e => e.User)
                .WithMany(u => u.Accounts)
                .HasForeignKey(e => e.UserId)
                .OnDelete(DeleteBehavior.Cascade);
        });

        // Session configuration
        modelBuilder.Entity<Session>(entity =>
        {
            entity.HasKey(e => e.Id);
            entity.HasIndex(e => e.Token).IsUnique(); // Session lookups by token
            entity.HasIndex(e => e.UserId); // User's sessions queries
            entity.HasIndex(e => e.ExpiresAt); // Cleanup/expiration queries
            entity.HasOne(e => e.User)
                .WithMany(u => u.Sessions)
                .HasForeignKey(e => e.UserId)
                .OnDelete(DeleteBehavior.Cascade);
        });

        // ═══════════════════════════════════════════════════════════════════════════════
        // EMAIL VERIFICATION - DISABLED FOR v0.1, WILL BE RE-ENABLED IN v0.2
        // ═══════════════════════════════════════════════════════════════════════════════
        // TODO v0.2: Uncomment this for email verification support
        /*
        // Verification configuration
        modelBuilder.Entity<Verification>(entity =>
        {
          entity.HasKey(e => e.Id);
        });
        */
        // ═══════════════════════════════════════════════════════════════════════════════
    }
}
