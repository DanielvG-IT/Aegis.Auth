using Aegis.Auth.Abstractions;
using Aegis.Auth.Passkeys.Abstractions;
using Microsoft.AspNetCore.Mvc;

namespace Aegis.Auth.Passkeys.Controllers
{
  /// <summary>
  /// Passkey authentication endpoints.
  /// These are added independently - no modification to core controllers needed.
  /// </summary>
  [ApiController]
  [Route("auth/passkey")]
  public sealed class PasskeyController : AegisControllerBase
  {
    private readonly IPasskeyService _passkeyService;
    private readonly IAegisSessionService _sessionService;

    public PasskeyController(
        IPasskeyService passkeyService,
        IAegisSessionService sessionService,
        IAegisLogger logger) : base(logger)
    {
      _passkeyService = passkeyService;
      _sessionService = sessionService;
    }

    /// <summary>
    /// POST /auth/passkey/register/options
    /// Generate options for passkey registration
    /// </summary>
    [HttpPost("register/options")]
    public async Task<IActionResult> GenerateRegistrationOptions([FromBody] GenerateRegistrationRequest request)
    {
      var result = await _passkeyService.GenerateRegistrationOptionsAsync(request.UserId);
      return result.Match(
          success => Ok(success),
          error => BadRequest(error)
      );
    }

    /// <summary>
    /// POST /auth/passkey/register/verify
    /// Verify and store a passkey registration
    /// </summary>
    [HttpPost("register/verify")]
    public async Task<IActionResult> VerifyRegistration([FromBody] VerifyRegistrationRequest request)
    {
      var result = await _passkeyService.VerifyRegistrationAsync(request.Attestation, request.UserId);
      return result.Match(
          success => Ok(new { credential = success }),
          error => BadRequest(error)
      );
    }

    /// <summary>
    /// POST /auth/passkey/sign-in/options
    /// Generate options for passkey authentication
    /// </summary>
    [HttpPost("sign-in/options")]
    public async Task<IActionResult> GenerateAuthenticationOptions([FromBody] GenerateAuthenticationRequest? request = null)
    {
      var result = await _passkeyService.GenerateAuthenticationOptionsAsync(request?.UserId);
      return result.Match(
          success => Ok(success),
          error => BadRequest(error)
      );
    }

    /// <summary>
    /// POST /auth/passkey/sign-in/verify
    /// Verify passkey authentication and create session
    /// </summary>
    [HttpPost("sign-in/verify")]
    public async Task<IActionResult> VerifyAuthentication([FromBody] VerifyAuthenticationRequest request)
    {
      // Verify the passkey assertion
      var authResult = await _passkeyService.VerifyAuthenticationAsync(request.Assertion);
      if (!authResult.IsSuccess)
      {
        return BadRequest(authResult.Error);
      }

      // Use shared session service (same as email/password sign-in)
      var session = await _sessionService.CreateSessionAsync(authResult.Value, HttpContext);

      return Ok(new
      {
        user = authResult.Value,
        session = session
      });
    }
  }

  // Request DTOs
  public record GenerateRegistrationRequest(string UserId);
  public record VerifyRegistrationRequest(object Attestation, string UserId);
  public record GenerateAuthenticationRequest(string? UserId);
  public record VerifyAuthenticationRequest(object Assertion);
}
