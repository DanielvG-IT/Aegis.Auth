using Aegis.Auth.Features.OAuth;
using Aegis.Auth.Options;

using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Options;

namespace Aegis.Auth.Infrastructure.Auth;

/// <summary>
/// OAuth schemes are registered for every supported provider at service registration time,
/// before the consumer's options are known. This provider drops the schemes of disabled
/// providers so ASP.NET Core never builds (and validates) handlers for them — otherwise every
/// request fails because an unconfigured provider has an empty ClientId.
/// </summary>
internal sealed class AegisAuthenticationSchemeProvider : AuthenticationSchemeProvider
{
    public AegisAuthenticationSchemeProvider(
        IOptions<AuthenticationOptions> authenticationOptions,
        IOptions<AegisAuthOptions> aegisOptions)
        : base(authenticationOptions)
    {
        OAuthOptions oauth = aegisOptions.Value.OAuth;
        foreach (OAuthProviderDefinition provider in OAuthProviderCatalog.All)
        {
            if (oauth.Enabled is false || provider.GetOptions(oauth).Enabled is false)
            {
                RemoveScheme(provider.Scheme);
            }
        }
    }
}
