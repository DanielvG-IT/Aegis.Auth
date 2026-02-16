using Aegis.Auth.Abstractions;
using Aegis.Auth.Entities;

using Microsoft.EntityFrameworkCore;

namespace Aegis.Auth.Tests.Helpers;

/// <summary>
/// Real EF Core in-memory DbContext implementing IAuthDbContext.
/// Provides genuine DbSet behavior (LINQ, tracking, constraints) for tests.
/// </summary>
internal sealed class TestDbContext : DbContext, IAuthDbContext
{
  public TestDbContext(DbContextOptions<TestDbContext> options) : base(options) { }

  public DbSet<User> Users => Set<User>();
  public DbSet<Account> Accounts => Set<Account>();
  public DbSet<Session> Sessions => Set<Session>();

  protected override void OnModelCreating(ModelBuilder modelBuilder)
  {
    modelBuilder.Entity<User>(e =>
    {
      e.HasKey(u => u.Id);
      e.HasIndex(u => u.Email).IsUnique();
    });

    modelBuilder.Entity<Account>(e =>
    {
      e.HasKey(a => a.Id);
      e.HasOne(a => a.User)
           .WithMany(u => u.Accounts)
           .HasForeignKey(a => a.UserId);
    });

    modelBuilder.Entity<Session>(e =>
    {
      e.HasKey(s => s.Id);
      e.HasOne(s => s.User)
           .WithMany(u => u.Sessions)
           .HasForeignKey(s => s.UserId);
    });
  }

  Task<int> IAuthDbContext.SaveChangesAsync(CancellationToken ct) => base.SaveChangesAsync(ct);
}
