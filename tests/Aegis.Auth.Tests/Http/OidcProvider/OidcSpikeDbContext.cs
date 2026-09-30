using Aegis.Auth.Abstractions;
using Aegis.Auth.Entities;
using Aegis.Auth.Extensions;

using Microsoft.EntityFrameworkCore;

namespace Aegis.Auth.Tests.Http.OidcProvider;

/// <summary>
/// A consumer-style DbContext holding the Aegis model and OpenIddict's entities side by side,
/// which is what the OIDC provider plugin's <c>ConfigureModel</c> (#95) would produce.
/// </summary>
internal sealed class OidcSpikeDbContext : DbContext, IAuthDbContext
{
    public OidcSpikeDbContext(DbContextOptions<OidcSpikeDbContext> options) : base(options) { }

    public DbSet<User> Users => Set<User>();
    public DbSet<Account> Accounts => Set<Account>();
    public DbSet<Session> Sessions => Set<Session>();
    public DbSet<AuthToken> AuthTokens => Set<AuthToken>();

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        modelBuilder.ApplyAegisAuthModel();

        // The ModelBuilder overload, not DbContextOptionsBuilder.UseOpenIddict(): the latter
        // replaces IModelCustomizer, which #95's recommended option (b) also replaces.
        modelBuilder.UseOpenIddict();
    }

    Task<int> IAuthDbContext.SaveChangesAsync(CancellationToken ct) => base.SaveChangesAsync(ct);
}
