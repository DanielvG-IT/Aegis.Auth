using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.DependencyInjection;

namespace Aegis.Auth.Plugins;

/// <summary>
/// HTTP helpers for Aegis and plugin endpoints.
/// </summary>
public static class AegisResults
{
    /// <summary>
    /// A ProblemDetails response whose status comes from the merged core and plugin error-code map
    /// (unknown codes map to 400). The code is returned as the <c>errorCode</c> extension.
    /// </summary>
    public static IResult Problem(HttpContext context, string? errorCode, string? message)
    {
        ArgumentNullException.ThrowIfNull(context);

        message ??= "An unexpected error occurred.";
        AegisPluginRegistry? registry = context.RequestServices?.GetService<AegisPluginRegistry>();
        var statusCode = registry?.GetStatusCode(errorCode) ?? AegisPluginRegistry.GetCoreStatusCode(errorCode);

        var title = ReasonPhrases.GetReasonPhrase(statusCode);
        if (string.IsNullOrEmpty(title))
        {
            title = "Error";
        }

        Dictionary<string, object?>? extensions = null;
        if (string.IsNullOrWhiteSpace(errorCode) is false)
        {
            extensions = new Dictionary<string, object?>
            {
                ["errorCode"] = errorCode,
            };
        }

        return Results.Problem(
            detail: message,
            title: title,
            statusCode: statusCode,
            type: $"https://httpstatuses.com/{statusCode}",
            instance: context.Request.Path,
            extensions: extensions);
    }
}
