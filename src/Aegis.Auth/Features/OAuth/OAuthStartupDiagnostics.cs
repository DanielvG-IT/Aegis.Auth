using Aegis.Auth.Logging;
using Aegis.Auth.Options;

using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Aegis.Auth.Features.OAuth;

/// <summary>
/// Logs security-relevant OAuth configuration warnings once at application startup.
/// </summary>
internal sealed class OAuthStartupDiagnostics(IOptions<AegisAuthOptions> optionsAccessor, ILoggerFactory loggerFactory) : IHostedService
{
    private readonly ILogger _logger = loggerFactory.CreateLogger<OAuthStartupDiagnostics>();

    public Task StartAsync(CancellationToken cancellationToken)
    {
        OAuthOptions oauth = optionsAccessor.Value.OAuth;
        if (oauth.Enabled is false)
        {
            return Task.CompletedTask;
        }

        foreach (OAuthProviderDefinition provider in OAuthProviderCatalog.All)
        {
            OAuthProviderOptions providerOptions = provider.GetOptions(oauth);
            if (providerOptions.Enabled && providerOptions.UsePkce is false)
            {
                _logger.OAuthPkceDisabled(provider.DisplayName);
            }
        }

        return Task.CompletedTask;
    }

    public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;
}
