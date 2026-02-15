using Aegis.Auth.Constants;

using Microsoft.AspNetCore.Mvc;

namespace Aegis.Auth.Abstractions
{
  public abstract class AegisControllerBase : ControllerBase
  {
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