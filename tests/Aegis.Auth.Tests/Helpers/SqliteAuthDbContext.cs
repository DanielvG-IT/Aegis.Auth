using Aegis.Auth.Abstractions;
using Aegis.Auth.Entities;
using Aegis.Auth.Extensions;

using Microsoft.EntityFrameworkCore;

namespace Aegis.Auth.Tests.Helpers;

/// <summary>
/// Relational DbContext using the real <see cref="ModelBuilderExtensions.ApplyAegisAuthModel"/>, for tests that
/// need constraints, transactions or <c>ExecuteUpdate</c>, which EF InMemory lacks.
/// </summary>
internal sealed class SqliteAuthDbContext(DbContextOptions<SqliteAuthDbContext> options) : DbContext(options), IAuthDbContext
{
    public DbSet<User> Users => Set<User>();
    public DbSet<Account> Accounts => Set<Account>();
    public DbSet<Session> Sessions => Set<Session>();
    public DbSet<AuthToken> AuthTokens => Set<AuthToken>();
    public DbSet<AegisKeyValue> AegisKeyValues => Set<AegisKeyValue>();

    protected override void OnModelCreating(ModelBuilder modelBuilder) => modelBuilder.ApplyAegisAuthModel();

    Task<int> IAuthDbContext.SaveChangesAsync(CancellationToken ct) => base.SaveChangesAsync(ct);
}
