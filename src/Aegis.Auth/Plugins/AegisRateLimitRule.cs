namespace Aegis.Auth.Plugins;

/// <summary>
/// A rate limit for one plugin endpoint. Values left <c>null</c> fall back to
/// <see cref="Options.RateLimitOptions"/>.
/// </summary>
/// <param name="Path">Endpoint path relative to the Aegis base path, starting with '/'.</param>
public sealed record AegisRateLimitRule(string Path)
{
    /// <summary>Maximum requests per client in <see cref="Window"/>.</summary>
    public int? MaxRequests { get; init; }

    /// <summary>Length of the fixed window.</summary>
    public TimeSpan? Window { get; init; }
}
