using Aegis.Auth.Constants;
using Aegis.Auth.Options;

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
                AuthErrors.Identity.InvalidCredentials => Unauthorized(result) as ObjectResult,
                AuthErrors.Identity.InvalidEmailOrPassword => Unauthorized(result) as ObjectResult,

                // 403 Forbidden
                AuthErrors.Identity.EmailNotVerified => StatusCode(403, result) as ObjectResult,
                AuthErrors.System.FeatureDisabled => StatusCode(403, result) as ObjectResult,

                // 404 Not Found
                AuthErrors.System.ProviderNotFound => NotFound(result) as ObjectResult,

                // 400 Bad Request (Default for validation/rest)
                _ => BadRequest(result) as ObjectResult
            };
        }
    }
}
