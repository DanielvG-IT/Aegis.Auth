using Aegis.Auth.Features.SecondaryStorage;

using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace Aegis.Auth.Extensions;

/// <summary>
/// Selects the <see cref="IAegisSecondaryStorage"/> implementation. <c>AddAegisAuth</c> registers the
/// in-memory one by default; these methods replace it and can be called before or after <c>AddAegisAuth</c>.
/// To plug in your own (e.g. Redis), register it as <see cref="IAegisSecondaryStorage"/> before <c>AddAegisAuth</c>
/// or with <see cref="ServiceCollectionDescriptorExtensions.Replace"/> after it.
/// </summary>
public static class SecondaryStorageServiceCollectionExtensions
{
    /// <summary>
    /// Stores secondary storage entries in the registered <see cref="IDistributedCache"/>, which must be
    /// registered separately (e.g. <c>AddStackExchangeRedisCache</c>).
    /// <para>
    /// <b>Not atomic:</b> <c>IncrementAsync</c> can lose updates and <c>SetIfNotExistsAsync</c> can succeed for
    /// more than one concurrent caller. A warning (event 9000) is logged at startup. Prefer
    /// <see cref="AddAegisDatabaseSecondaryStorage"/> or a Redis implementation where that matters.
    /// </para>
    /// </summary>
    public static IServiceCollection AddAegisDistributedCacheSecondaryStorage(this IServiceCollection services)
    {
        ArgumentNullException.ThrowIfNull(services);
        services.TryAddSingleton(TimeProvider.System);
        services.Replace(ServiceDescriptor.Singleton<IAegisSecondaryStorage>(sp => new DistributedCacheSecondaryStorage(
            sp.GetService<IDistributedCache>() ?? throw new InvalidOperationException(
                "AddAegisDistributedCacheSecondaryStorage() requires an IDistributedCache registration, e.g. AddStackExchangeRedisCache() or AddDistributedMemoryCache()."),
            sp.GetRequiredService<TimeProvider>())));
        return services;
    }

    /// <summary>
    /// Stores secondary storage entries in the <c>AegisKeyValues</c> table of your <c>IAuthDbContext</c>, shared by
    /// every instance. Operations are atomic through primary-key conflicts and conditional updates. Requires a
    /// relational EF Core provider and a migration that creates the table.
    /// </summary>
    public static IServiceCollection AddAegisDatabaseSecondaryStorage(this IServiceCollection services)
    {
        ArgumentNullException.ThrowIfNull(services);
        services.TryAddSingleton(TimeProvider.System);
        services.Replace(ServiceDescriptor.Singleton<IAegisSecondaryStorage, DatabaseSecondaryStorage>());
        return services;
    }
}
