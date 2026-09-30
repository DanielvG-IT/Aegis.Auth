using Aegis.Auth.Extensions;

using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;

namespace Aegis.Auth.Infrastructure.EntityFramework;

/// <summary>
/// Applies the core Aegis model and every plugin's model, then hands over to the provider's customizer,
/// which runs the app's <c>OnModelCreating</c>. The app therefore has the last word on every mapping.
/// </summary>
internal sealed class AegisAuthModelCustomizer(IModelCustomizer inner) : IModelCustomizer
{
    internal IModelCustomizer Inner { get; } = inner;

    public void Customize(ModelBuilder modelBuilder, DbContext context)
    {
        // Read from the context rather than capturing at construction: EF shares this service across
        // every context whose options only differ in the plugin set.
        AegisAuthDbContextOptionsExtension? extension = context.GetService<IDbContextOptions>()
            .FindExtension<AegisAuthDbContextOptionsExtension>();

        if (extension is not null)
        {
            modelBuilder.ApplyAegisAuthModel(extension.TokenEncryption);
            foreach (Plugins.AegisPlugin plugin in extension.Plugins)
            {
                plugin.ConfigureModel(modelBuilder);
            }
        }

        Inner.Customize(modelBuilder, context);
    }
}
