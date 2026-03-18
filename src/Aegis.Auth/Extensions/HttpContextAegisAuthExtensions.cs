using Aegis.Auth.Abstractions;

using Microsoft.AspNetCore.Http;

namespace Aegis.Auth.Extensions;

public static class HttpContextAegisAuthExtensions
{
    private const string AegisAuthContextItemKey = "aegis.auth.context";

    public static void SetAegisAuthContext(this HttpContext httpContext, AegisAuthContext authContext)
    {
        ArgumentNullException.ThrowIfNull(httpContext);
        ArgumentNullException.ThrowIfNull(authContext);

        httpContext.Items[AegisAuthContextItemKey] = authContext;
    }

    public static AegisAuthContext? GetAegisAuthContext(this HttpContext httpContext)
    {
        ArgumentNullException.ThrowIfNull(httpContext);

        return httpContext.Items.TryGetValue(AegisAuthContextItemKey, out var value)
            ? value as AegisAuthContext
            : null;
    }
}
