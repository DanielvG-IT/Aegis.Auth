using Aegis.Auth.Abstractions;
using Aegis.Auth.Plugins;

using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

namespace Aegis.Auth.Infrastructure.EntityFramework;

/// <summary>
/// Fails startup when a plugin contributes EF model but the Aegis context was configured without
/// <c>UseAegisAuth</c>. Its tables would otherwise be missing from the model and migrations, and the
/// plugin would only fail on its first query.
/// </summary>
internal sealed class PluginModelStartupCheck(AegisPluginRegistry registry, IServiceScopeFactory scopeFactory) : IHostedService
{
    public Task StartAsync(CancellationToken cancellationToken)
    {
        var modelPlugins = registry.Plugins.Where(ContributesModel).Select(p => p.Id).ToList();
        if (modelPlugins.Count == 0)
        {
            return Task.CompletedTask;
        }

        using IServiceScope scope = scopeFactory.CreateScope();
        if (scope.ServiceProvider.GetService<IAuthDbContext>() is not DbContext context)
        {
            return Task.CompletedTask;
        }

        if (context.GetService<IDbContextOptions>().FindExtension<AegisAuthDbContextOptionsExtension>() is null)
        {
            throw new InvalidOperationException(
                $"Aegis plugins {string.Join(", ", modelPlugins.Select(id => $"'{id}'"))} add tables, but {context.GetType().Name} is not configured with UseAegisAuth. " +
                $"Register it as AddDbContext<{context.GetType().Name}>((sp, o) => o.Use…(…).UseAegisAuth(sp)).");
        }

        return Task.CompletedTask;
    }

    public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;

    private static bool ContributesModel(AegisPlugin plugin) =>
        plugin.GetType().GetMethod(nameof(AegisPlugin.ConfigureModel), [typeof(ModelBuilder)])?.DeclaringType != typeof(AegisPlugin);
}
