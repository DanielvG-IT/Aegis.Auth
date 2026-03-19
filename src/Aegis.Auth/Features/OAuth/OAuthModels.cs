using Aegis.Auth.Entities;

namespace Aegis.Auth.Features.OAuth;

public sealed class ExternalIdentity
{
    public required string ProviderId { get; init; }
    public required string ProviderAccountId { get; init; }
    public string? Email { get; init; }
    public bool EmailVerified { get; init; }
    public string? Name { get; init; }
    public string? Image { get; init; }
    public string? AccessToken { get; init; }
    public string? RefreshToken { get; init; }
    public DateTime? AccessTokenExpiresAt { get; init; }
    public DateTime? RefreshTokenExpiresAt { get; init; }
    public string? Scope { get; init; }
    public string? IdToken { get; init; }
}

public sealed class OAuthSignInInput
{
    public required ExternalIdentity Identity { get; init; }
    public required string UserAgent { get; init; }
    public required string IpAddress { get; init; }
    public bool RememberMe { get; init; } = true;
    public string? Callback { get; init; }
}

public sealed class OAuthSignInResult
{
    public required User User { get; init; }
    public required Session Session { get; init; }
    public required Account Account { get; init; }
    public required bool CreatedUser { get; init; }
    public required bool LinkedByEmail { get; init; }
    public required string? CallbackUrl { get; init; }
}
