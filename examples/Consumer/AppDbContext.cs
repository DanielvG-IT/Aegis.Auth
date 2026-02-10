using Aegis.Auth;
using Aegis.Auth.Abstractions;
using Aegis.Auth.Entities;
using Aegis.Auth.Passkeys;
using Microsoft.EntityFrameworkCore;

namespace ExampleApp
{
  /// <summary>
  /// Example consumer DbContext showing how to integrate core + feature entities.
  /// </summary>
  public class AppDbContext : DbContext, IAuthDbContext
  {
    public AppDbContext(DbContextOptions<AppDbContext> options) : base(options) { }

    // ========================================
    // REQUIRED: Core Aegis.Auth entities
    // ========================================
    public DbSet<User> Users => Set<User>();
    public DbSet<Account> Accounts => Set<Account>();
    public DbSet<Session> Sessions => Set<Session>();
    public DbSet<Verification> Verifications => Set<Verification>();

    // ========================================
    // OPTIONAL: Feature entities (add as needed)
    // ========================================

    /// <summary>
    /// Required if using Aegis.Auth.Passkeys
    /// </summary>
    public DbSet<PasskeyCredential> PasskeyCredentials => Set<PasskeyCredential>();

    // Uncomment if using Aegis.Auth.Totp:
    // public DbSet<TotpDevice> TotpDevices => Set<TotpDevice>();

    // Uncomment if using Aegis.Auth.SSO:
    // public DbSet<OAuthConnection> OAuthConnections => Set<OAuthConnection>();

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
      base.OnModelCreating(modelBuilder);

      // Configure core entities
      modelBuilder.Entity<User>(entity =>
      {
        entity.HasKey(e => e.Id);
        entity.HasIndex(e => e.Email).IsUnique();
      });

      modelBuilder.Entity<Session>(entity =>
      {
        entity.HasKey(e => e.Id);
        entity.HasIndex(e => e.Token).IsUnique();
        entity.HasIndex(e => e.UserId);
      });

      // Configure feature entities
      modelBuilder.Entity<PasskeyCredential>(entity =>
      {
        entity.HasKey(e => e.Id);
        entity.HasIndex(e => e.UserId);
      });
    }
  }
}
