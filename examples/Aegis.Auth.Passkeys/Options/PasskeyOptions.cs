namespace Aegis.Auth.Passkeys.Options
{
  /// <summary>
  /// Configuration options for Passkey authentication.
  /// </summary>
  public sealed class PasskeyOptions
  {
    /// <summary>
    /// Relying Party name (typically your app name).
    /// </summary>
    public string RelyingPartyName { get; set; } = string.Empty;

    /// <summary>
    /// Relying Party ID (typically your domain, e.g., "example.com").
    /// </summary>
    public string RelyingPartyId { get; set; } = string.Empty;

    /// <summary>
    /// Whether to require user verification (UV) during authentication.
    /// </summary>
    public bool RequireUserVerification { get; set; } = true;

    /// <summary>
    /// Timeout for passkey ceremonies in milliseconds.
    /// </summary>
    public int TimeoutMs { get; set; } = 60000;
  }
}
