using Microsoft.AspNetCore.Http;

namespace Aegis.Auth.Http.Internal;

internal static class HttpContextAegisExtensions
{
    public static string GetClientUserAgent(this HttpContext context)
        => context.Request.Headers.UserAgent.ToString() ?? "unknown";

    public static string GetClientIpAddress(this HttpContext context)
        => context.Connection.RemoteIpAddress?.ToString() ?? "unknown";
}
