using System.Security.Claims;
using System.Text.Encodings.Web;

using Aegis.Auth.Abstractions;
using Aegis.Auth.Extensions;
using Aegis.Auth.Options;

using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Aegis.Auth.Infrastructure.Auth;

/// <summary>
/// ASP.NET Core authentication handler that validates Aegis session cookies and
/// populates HttpContext.User so that [Authorize] and RequireAuthorization() work natively.
/// </summary>
internal sealed class AegisAuthenticationHandler(
    IOptionsMonitor<AegisAuthSchemeOptions> options,
    ILoggerFactory logger,
    UrlEncoder encoder,
    IAegisAuthContextAccessor contextAccessor)
    : AuthenticationHandler<AegisAuthSchemeOptions>(options, logger, encoder)
{
    protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        AegisAuthContext? authContext = await contextAccessor.GetCurrentAsync(Context, Context.RequestAborted);
        if (authContext is null)
            return AuthenticateResult.NoResult();

        // Store for endpoint code that calls httpContext.GetAegisAuthContext().
        Context.SetAegisAuthContext(authContext);

        var claims = new[]
        {
            new Claim(ClaimTypes.NameIdentifier, authContext.UserId),
        };
        var identity = new ClaimsIdentity(claims, Scheme.Name);
        var principal = new ClaimsPrincipal(identity);
        var ticket = new AuthenticationTicket(principal, Scheme.Name);
        return AuthenticateResult.Success(ticket);
    }
}
