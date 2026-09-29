namespace Aegis.Auth.Options;

/// <summary>
/// Limits are kept in memory per application instance; with N instances behind a load balancer a
/// client can make up to N times as many attempts. When running behind a reverse proxy, configure
/// the forwarded headers middleware so client IPs are not all seen as the proxy's address.
/// </summary>
public sealed class RateLimitOptions
{
    /// <summary>
    /// Enable rate limiting on auth endpoints. Default: true.
    /// </summary>
    public bool Enabled { get; set; } = true;

    /// <summary>
    /// Maximum requests per client IP per minute, counted separately for each endpoint
    /// (sign-in, sign-up, password reset, email verification). IPv6 clients are grouped by /64. Default: 10.
    /// </summary>
    public int MaxAttemptsPerIpPerMinute { get; set; } = 10;

    /// <summary>
    /// Maximum sign-in attempts per email address per 15 minutes, successful or not. Default: 5.
    /// This prevents brute-forcing a specific user account even from rotating IPs.
    /// </summary>
    public int MaxAttemptsPerEmailPer15Minutes { get; set; } = 5;
}
