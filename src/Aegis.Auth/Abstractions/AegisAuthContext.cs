namespace Aegis.Auth.Abstractions;

public sealed class AegisAuthContext
{
    public required string UserId { get; init; }
    public required string SessionToken { get; init; }
    public required DateTime ExpiresAt { get; init; }
    public bool IsFromCookieCache { get; init; }
}
