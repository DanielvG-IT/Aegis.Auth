using Aegis.Auth.Features.OAuth;
using Aegis.Auth.Infrastructure.EntityFramework;
using Aegis.Auth.Plugins;

using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.Extensions.DependencyInjection;

namespace Aegis.Auth.Extensions;

public static class DbContextOptionsBuilderExtensions
{
    /// <summary>
    /// Applies the Aegis model and the model of every registered plugin to this context, before its
    /// <c>OnModelCreating</c> runs. OAuth tokens on <see cref="Entities.Account"/> are encrypted at rest.
    /// With this, <c>OnModelCreating</c> no longer needs <c>ApplyAegisAuthModel</c>; calling it anyway is harmless.
    /// Call it after the database provider, e.g.
    /// <c>AddDbContext&lt;AppDbContext&gt;((sp, o) =&gt; o.UseSqlite(cs).UseAegisAuth(sp))</c>.
    /// </summary>
    public static DbContextOptionsBuilder UseAegisAuth(this DbContextOptionsBuilder optionsBuilder, IServiceProvider serviceProvider)
    {
        ArgumentNullException.ThrowIfNull(optionsBuilder);
        ArgumentNullException.ThrowIfNull(serviceProvider);

        if (optionsBuilder.Options.Extensions.Any(e => e.Info.IsDatabaseProvider) is false)
        {
            throw new InvalidOperationException(
                "Configure the database provider (e.g. UseSqlite) before calling UseAegisAuth, so Aegis can extend the provider's model building.");
        }

        AegisPluginRegistry registry = serviceProvider.GetService<AegisPluginRegistry>()
            ?? throw new InvalidOperationException("UseAegisAuth requires AddAegisAuth<TContext>() to be registered.");

        var extension = new AegisAuthDbContextOptionsExtension(
            [.. registry.Plugins],
            serviceProvider.GetService<ITokenEncryptionService>());

        ((IDbContextOptionsBuilderInfrastructure)optionsBuilder).AddOrUpdateExtension(extension);
        return optionsBuilder;
    }

    /// <inheritdoc cref="UseAegisAuth(DbContextOptionsBuilder, IServiceProvider)"/>
    public static DbContextOptionsBuilder<TContext> UseAegisAuth<TContext>(this DbContextOptionsBuilder<TContext> optionsBuilder, IServiceProvider serviceProvider)
        where TContext : DbContext =>
        (DbContextOptionsBuilder<TContext>)UseAegisAuth((DbContextOptionsBuilder)optionsBuilder, serviceProvider);
}
