using Aegis.Auth.Abstractions;
using Aegis.Auth.Entities;

using Microsoft.EntityFrameworkCore;

namespace Aegis.Auth.Sample.Data;

public class SampleAuthDbContext(DbContextOptions<SampleAuthDbContext> options) : DbContext(options), IAuthDbContext
{
  public DbSet<User> Users { get; set; } = null!;
  public DbSet<Account> Accounts { get; set; } = null!;
  public DbSet<Session> Sessions { get; set; } = null!;
  public DbSet<Verification> Verifications { get; set; } = null!;

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
      entity.HasOne(e => e.User)
              .WithMany(u => u.Accounts)
              .HasForeignKey(e => e.UserId)
              .OnDelete(DeleteBehavior.Cascade);
    });

    // Session configuration
    modelBuilder.Entity<Session>(entity =>
    {
      entity.HasKey(e => e.Id);
      entity.HasOne(e => e.User)
              .WithMany(u => u.Sessions)
              .HasForeignKey(e => e.UserId)
              .OnDelete(DeleteBehavior.Cascade);
    });

    // Verification configuration
    modelBuilder.Entity<Verification>(entity =>
    {
      entity.HasKey(e => e.Id);
    });
  }
}
