using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;

namespace Aegis.Auth.Infrastructure.EntityFramework;

/// <summary>
/// EF caches one model per context type. Adding the plugin set to the key keeps contexts of the same type
/// but with different plugins (e.g. across test hosts) from sharing a model.
/// </summary>
internal sealed class AegisAuthModelCacheKeyFactory(IModelCacheKeyFactory inner) : IModelCacheKeyFactory
{
    public object Create(DbContext context, bool designTime)
    {
        var key = inner.Create(context, designTime);
        AegisAuthDbContextOptionsExtension? extension = context.GetService<IDbContextOptions>()
            .FindExtension<AegisAuthDbContextOptionsExtension>();

        return extension is null ? key : (key, extension.ModelKey);
    }
}
