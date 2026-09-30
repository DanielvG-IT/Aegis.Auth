using Aegis.Auth.Features.OAuth;
using Aegis.Auth.Plugins;

using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace Aegis.Auth.Infrastructure.EntityFramework;

/// <summary>
/// Carries the plugin set into EF, whose model building has no access to the app's services.
/// Added by <c>UseAegisAuth</c>; it wraps the provider's model customizer and cache-key factory.
/// </summary>
internal sealed class AegisAuthDbContextOptionsExtension(
    IReadOnlyList<AegisPlugin> plugins,
    ITokenEncryptionService? tokenEncryption) : IDbContextOptionsExtension
{
    private DbContextOptionsExtensionInfo? _info;

    public IReadOnlyList<AegisPlugin> Plugins { get; } = plugins;

    public ITokenEncryptionService? TokenEncryption { get; } = tokenEncryption;

    /// <summary>
    /// Everything the Aegis part of the model depends on; part of EF's model cache key.
    /// </summary>
    public string ModelKey { get; } =
        $"{string.Join(',', plugins.Select(p => p.Id))}|encrypted-tokens:{tokenEncryption is not null}";

    public DbContextOptionsExtensionInfo Info => _info ??= new ExtensionInfo(this);

    public void ApplyServices(IServiceCollection services)
    {
        Decorate<IModelCustomizer>(services, inner => new AegisAuthModelCustomizer(inner));
        Decorate<IModelCacheKeyFactory>(services, inner => new AegisAuthModelCacheKeyFactory(inner));
    }

    public void Validate(IDbContextOptions options) { }

    /// <summary>
    /// Wraps the provider's registration (e.g. RelationalModelCustomizer) instead of replacing it,
    /// so provider behavior such as DbFunction discovery keeps working.
    /// </summary>
    private static void Decorate<TService>(IServiceCollection services, Func<TService, TService> decorate)
        where TService : class
    {
        ServiceDescriptor inner = services.LastOrDefault(d => d.ServiceType == typeof(TService))
            ?? throw new InvalidOperationException(
                $"UseAegisAuth could not find EF's {typeof(TService).Name}. Configure the database provider before calling UseAegisAuth.");

        services.Replace(ServiceDescriptor.Describe(
            typeof(TService),
            sp => decorate(CreateInner<TService>(sp, inner)),
            inner.Lifetime));
    }

    private static TService CreateInner<TService>(IServiceProvider sp, ServiceDescriptor descriptor)
        where TService : class
    {
        if (descriptor.ImplementationInstance is TService instance)
        {
            return instance;
        }

        if (descriptor.ImplementationFactory is not null)
        {
            return (TService)descriptor.ImplementationFactory(sp);
        }

        return (TService)ActivatorUtilities.CreateInstance(sp, descriptor.ImplementationType!);
    }

    private sealed class ExtensionInfo(AegisAuthDbContextOptionsExtension extension) : DbContextOptionsExtensionInfo(extension)
    {
        private new AegisAuthDbContextOptionsExtension Extension => (AegisAuthDbContextOptionsExtension)base.Extension;

        public override bool IsDatabaseProvider => false;

        public override string LogFragment => $"AegisAuth(plugins: {string.Join(", ", Extension.Plugins.Select(p => p.Id))}) ";

        // The registered services read the plugin set from the context at model-build time, so every
        // plugin set can share one internal service provider. The model cache key keeps the models apart.
        public override int GetServiceProviderHashCode() => 0;

        public override bool ShouldUseSameServiceProvider(DbContextOptionsExtensionInfo other) => other is ExtensionInfo;

        public override void PopulateDebugInfo(IDictionary<string, string> debugInfo) =>
            debugInfo["AegisAuth:ModelKey"] = Extension.ModelKey.GetHashCode(StringComparison.Ordinal).ToString(System.Globalization.CultureInfo.InvariantCulture);
    }
}
