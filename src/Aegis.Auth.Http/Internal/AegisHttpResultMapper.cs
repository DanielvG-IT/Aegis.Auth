using Aegis.Auth.Constants;

using Microsoft.AspNetCore.Http;

namespace Aegis.Auth.Http.Internal;

internal static class AegisHttpResultMapper
{
  public static IResult MapError(HttpContext context, string? errorCode, string? message)
  {
    message ??= "An unexpected error occurred.";
    var statusCode = errorCode switch
    {
      AuthErrors.Identity.InvalidCredentials => StatusCodes.Status401Unauthorized,
      AuthErrors.Identity.InvalidEmailOrPassword => StatusCodes.Status401Unauthorized,
      AuthErrors.Identity.EmailNotVerified => StatusCodes.Status403Forbidden,
      AuthErrors.System.FeatureDisabled => StatusCodes.Status403Forbidden,
      AuthErrors.System.ProviderNotFound => StatusCodes.Status404NotFound,
      AuthErrors.Session.SessionNotFound => StatusCodes.Status404NotFound,
      AuthErrors.System.InternalError => StatusCodes.Status500InternalServerError,
      AuthErrors.System.FailedToCreateSession => StatusCodes.Status500InternalServerError,
      _ => StatusCodes.Status400BadRequest,
    };

    var title = statusCode switch
    {
      StatusCodes.Status401Unauthorized => "Unauthorized",
      StatusCodes.Status403Forbidden => "Forbidden",
      StatusCodes.Status404NotFound => "Not Found",
      StatusCodes.Status500InternalServerError => "Internal Server Error",
      _ => "Bad Request",
    };

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
