using Aegis.Auth.Constants;
using Aegis.Auth.Options;

using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace Aegis.Auth.Abstractions
{
    public abstract class AegisControllerBase : ControllerBase
    {
        /// <summary>
        /// Validates that a callback URL is safe to redirect to.
        /// Allows relative URLs and absolute URLs whose origin is in TrustedOrigins.
        /// Returns null if the callback is invalid or untrusted.
        /// </summary>
        protected static string? ValidateCallback(string? callback, AegisAuthOptions options)
        {
            if (string.IsNullOrWhiteSpace(callback))
                return null;

            // Allow relative paths (e.g. "/dashboard")
            if (callback.StartsWith('/') && !callback.StartsWith("//"))
                return callback;

            // Reject anything that isn't a valid absolute URI
            if (!Uri.TryCreate(callback, UriKind.Absolute, out Uri? uri))
                return null;

            // Only allow http/https schemes
            if (uri.Scheme is not ("http" or "https"))
                return null;

            // Must match a trusted origin
            if (options.TrustedOrigins is null || options.TrustedOrigins.Count == 0)
                return null;

            var origin = $"{uri.Scheme}://{uri.Authority}";
            return options.TrustedOrigins.Contains(origin, StringComparer.OrdinalIgnoreCase)
              ? callback
              : null;
        }

        protected IActionResult HandleResult<T>(Result<T> result)
        {
            if (result.IsSuccess) return Ok(result.Value);
            return MapErrorToResponse(result.ToResult());
        }

        protected IActionResult HandleResult(Result result)
        {
            if (result.IsSuccess) return Ok();
            return MapErrorToResponse(result);
        }

        private ObjectResult MapErrorToResponse(Result result)
        {
            return result.ErrorCode switch
            {
                // 401 Unauthorized
                AuthErrors.Identity.InvalidCredentials => CreateProblem(result, StatusCodes.Status401Unauthorized, "Unauthorized"),
                AuthErrors.Identity.InvalidEmailOrPassword => CreateProblem(result, StatusCodes.Status401Unauthorized, "Unauthorized"),

                // 403 Forbidden
                AuthErrors.Identity.EmailNotVerified => CreateProblem(result, StatusCodes.Status403Forbidden, "Forbidden"),
                AuthErrors.System.FeatureDisabled => CreateProblem(result, StatusCodes.Status403Forbidden, "Forbidden"),

                // 404 Not Found
                AuthErrors.System.ProviderNotFound => CreateProblem(result, StatusCodes.Status404NotFound, "Not Found"),
                AuthErrors.Session.SessionNotFound => CreateProblem(result, StatusCodes.Status404NotFound, "Not Found"),

                // 500 Internal Server Error
                AuthErrors.System.InternalError => CreateProblem(result, StatusCodes.Status500InternalServerError, "Internal Server Error"),
                AuthErrors.System.FailedToCreateSession => CreateProblem(result, StatusCodes.Status500InternalServerError, "Internal Server Error"),

                // 400 Bad Request (Default for validation/rest)
                _ => CreateProblem(result, StatusCodes.Status400BadRequest, "Bad Request")
            };
        }

        private ObjectResult CreateProblem(Result result, int statusCode, string title)
        {
            var problem = new ProblemDetails
            {
                Status = statusCode,
                Title = title,
                Detail = result.Message,
                Type = $"https://httpstatuses.com/{statusCode}",
                Instance = HttpContext.Request.Path,
            };

            if (string.IsNullOrWhiteSpace(result.ErrorCode) is false)
            {
                problem.Extensions["errorCode"] = result.ErrorCode;
            }

            return StatusCode(statusCode, problem) as ObjectResult
                ?? new ObjectResult(problem) { StatusCode = statusCode };
        }
    }
}
