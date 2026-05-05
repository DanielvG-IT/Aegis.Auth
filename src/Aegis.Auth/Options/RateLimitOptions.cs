namespace Aegis.Auth.Options;

public sealed class RateLimitOptions
{
    /// <summary>
    /// Enable rate limiting on auth endpoints. Default: true.
    /// </summary>
    public bool Enabled { get; set; } = true;

    /// <summary>
    /// Maximum sign-in/sign-up attempts per IP address per minute. Default: 10.
    /// </summary>
    public int MaxAttemptsPerIpPerMinute { get; set; } = 10;

    /// <summary>
    /// Maximum sign-in/sign-up attempts per email address per 15 minutes. Default: 5.
    /// This prevents brute-forcing a specific user account even from rotating IPs.
    /// </summary>
    public int MaxAttemptsPerEmailPer15Minutes { get; set; } = 5;
}
