namespace Aegis.Auth.Options;

/// <summary>
/// Persistent per-account lockout after repeated failed password sign-ins.
/// Opt-in: anyone who knows an email address can trigger a lockout, so enabling this trades
/// brute-force resistance for a denial-of-service vector against that account.
/// </summary>
public sealed class AccountLockoutOptions
{
    public bool Enabled { get; set; } = false;

    /// <summary>
    /// Consecutive failed password attempts that lock the account. Default: 10.
    /// </summary>
    public int MaxFailedAttempts { get; set; } = 10;

    /// <summary>
    /// How long a temporary lockout lasts. Default: 15 minutes.
    /// </summary>
    public TimeSpan LockoutDuration { get; set; } = TimeSpan.FromMinutes(15);

    /// <summary>
    /// When true, a locked account stays locked until
    /// <c>IAccountLockoutService.UnlockAsync</c> is called (e.g. from an admin endpoint).
    /// </summary>
    public bool PermanentLockout { get; set; } = false;
}
