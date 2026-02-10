using Aegis.Auth.Passkeys;
using Aegis.Auth.Result;

namespace Aegis.Auth.Passkeys.Abstractions
{
  /// <summary>
  /// Service interface for Passkey authentication operations.
  /// </summary>
  public interface IPasskeyService
  {
    /// <summary>
    /// Generates WebAuthn credential creation options for registration.
    /// </summary>
    Task<Result<object>> GenerateRegistrationOptionsAsync(string userId, CancellationToken cancellationToken = default);

    /// <summary>
    /// Verifies and stores a newly registered passkey credential.
    /// </summary>
    Task<Result<PasskeyCredential>> VerifyRegistrationAsync(object attestationResponse, string userId, CancellationToken cancellationToken = default);

    /// <summary>
    /// Generates WebAuthn credential request options for authentication.
    /// </summary>
    Task<Result<object>> GenerateAuthenticationOptionsAsync(string? userId = null, CancellationToken cancellationToken = default);

    /// <summary>
    /// Verifies a passkey authentication assertion and returns the authenticated user.
    /// </summary>
    Task<Result<Entities.User>> VerifyAuthenticationAsync(object assertionResponse, CancellationToken cancellationToken = default);
  }
}
