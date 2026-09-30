using Aegis.Auth.Logging;

using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace Aegis.Auth.Features.SecondaryStorage;

/// <summary>
/// Resolves the configured secondary storage once at startup, so a missing dependency fails fast,
/// and warns when the non-atomic <see cref="DistributedCacheSecondaryStorage"/> is in use.
/// </summary>
internal sealed class SecondaryStorageStartupDiagnostics(IServiceScopeFactory scopeFactory, ILoggerFactory loggerFactory) : IHostedService
{
    private readonly ILogger _logger = loggerFactory.CreateLogger<SecondaryStorageStartupDiagnostics>();

    public Task StartAsync(CancellationToken cancellationToken)
    {
        // A scope, in case a consumer registered a scoped implementation.
        using IServiceScope scope = scopeFactory.CreateScope();
        if (scope.ServiceProvider.GetRequiredService<IAegisSecondaryStorage>() is DistributedCacheSecondaryStorage)
        {
            _logger.SecondaryStorageNotAtomic();
        }

        return Task.CompletedTask;
    }

    public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;
}
