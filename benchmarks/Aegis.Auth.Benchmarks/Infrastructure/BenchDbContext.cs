using Aegis.Auth.Abstractions;
using Aegis.Auth.Entities;
using Aegis.Auth.Extensions;

using Microsoft.EntityFrameworkCore;

namespace Aegis.Auth.Benchmarks.Infrastructure;

/// <summary>
/// The Aegis model with nothing added, as a consumer would map it with <c>ApplyAegisAuthModel</c>.
/// </summary>
public sealed class BenchDbContext(DbContextOptions<BenchDbContext> options) : DbContext(options), IAuthDbContext
{
    public DbSet<User> Users => Set<User>();
    public DbSet<Account> Accounts => Set<Account>();
    public DbSet<Session> Sessions => Set<Session>();
    public DbSet<AuthToken> AuthTokens => Set<AuthToken>();
    public DbSet<AegisKeyValue> AegisKeyValues => Set<AegisKeyValue>();

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        modelBuilder.ApplyAegisAuthModel();
    }

    Task<int> IAuthDbContext.SaveChangesAsync(CancellationToken ct) => base.SaveChangesAsync(ct);
}
