using Aegis.Auth.Plugins;

using Microsoft.AspNetCore.Http;

namespace Aegis.Auth.Http.Internal;

internal static class AegisHttpResultMapper
{
    public static IResult MapError(HttpContext context, string? errorCode, string? message) =>
        AegisResults.Problem(context, errorCode, message);
}
