using Aegis.Auth.Constants;

using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Routing;

namespace Aegis.Auth.Http.Extensions;

/// <summary>
/// Convenience wrappers that protect minimal API endpoints with the Aegis
/// authentication scheme. These call into the native ASP.NET Core authorization
/// pipeline, so app.UseAuthentication() and app.UseAuthorization() must be
/// present in Program.cs.
///
/// The AegisAuthenticationHandler runs during UseAuthentication() and:
///  1. Validates the session cookie.
///  2. Populates HttpContext.User with the user-id claim.
///  3. Stores AegisAuthContext in HttpContext.Items for endpoint code that
///     calls httpContext.GetAegisAuthContext().
/// </summary>
public static class AegisAuthProtectionExtensions
{
    public static RouteGroupBuilder RequireAegisAuth(this RouteGroupBuilder group)
    {
        ArgumentNullException.ThrowIfNull(group);

        group.RequireAuthorization(new AuthorizeAttribute
        {
            AuthenticationSchemes = AegisDefaults.AuthenticationScheme
        });
        return group;
    }

    public static RouteHandlerBuilder RequireAegisAuth(this RouteHandlerBuilder builder)
    {
        ArgumentNullException.ThrowIfNull(builder);

        builder.RequireAuthorization(new AuthorizeAttribute
        {
            AuthenticationSchemes = AegisDefaults.AuthenticationScheme
        });
        return builder;
    }
}
