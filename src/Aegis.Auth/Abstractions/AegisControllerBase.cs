using Aegis.Auth.Constants;

using Microsoft.AspNetCore.Mvc;

namespace Aegis.Auth.Abstractions
{
  [Route("api/auth")]
  public abstract class AegisControllerBase : ControllerBase
  {
    protected IActionResult HandleResult<T>(Result<T> result)
    {
      if (result.IsSuccess) return Ok(result.Value);

      // Using your actual constants for type-safety
      return result.ErrorCode switch
      {
        // 401 Unauthorized
        AuthErrors.Identity.InvalidCredentials => Unauthorized(result),
        AuthErrors.Identity.InvalidEmailOrPassword => Unauthorized(result),

        // 403 Forbidden
        AuthErrors.Identity.EmailNotVerified => StatusCode(403, result),
        AuthErrors.System.FeatureDisabled => StatusCode(403, result),

        // 404 Not Found
        AuthErrors.System.ProviderNotFound => NotFound(result),

        // 400 Bad Request (Default for validation/rest)
        _ => BadRequest(result)
      };
    }
  }
}