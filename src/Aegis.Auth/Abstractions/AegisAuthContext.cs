namespace Aegis.Auth.Abstractions;

public sealed class AegisAuthContext
{
    public required string UserId { get; init; }

    /// <summary>
    /// Id of the current <see cref="Entities.Session"/> row, for features that store per-session state
    /// (e.g. the active organization).
    /// </summary>
    public required string SessionId { get; init; }
    public required string SessionToken { get; init; }
    public required DateTime ExpiresAt { get; init; }
    public bool IsFromCookieCache { get; init; }
}
