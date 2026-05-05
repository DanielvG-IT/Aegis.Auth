using Aegis.Auth.Options;

using Microsoft.Extensions.Options;

namespace Aegis.Auth.Features.RateLimit;

public interface IRateLimitService
{
    /// <summary>
    /// Checks if an operation (by IP) is allowed. Returns true if allowed; false if rate limit exceeded.
    /// </summary>
    bool IsAllowedByIp(string ipAddress, string operation = "auth");

    /// <summary>
    /// Checks if an operation (by email) is allowed. Returns true if allowed; false if rate limit exceeded.
    /// </summary>
    bool IsAllowedByEmail(string email, string operation = "auth");

    /// <summary>
    /// Records a failed attempt by IP.
    /// </summary>
    void RecordFailureByIp(string ipAddress, string operation = "auth");

    /// <summary>
    /// Records a failed attempt by email.
    /// </summary>
    void RecordFailureByEmail(string email, string operation = "auth");

    /// <summary>
    /// Resets the failure count for an IP (e.g., after successful auth).
    /// </summary>
    void ResetIp(string ipAddress, string operation = "auth");

    /// <summary>
    /// Resets the failure count for an email (e.g., after successful auth).
    /// </summary>
    void ResetEmail(string email, string operation = "auth");
}

/// <summary>
/// Simple in-memory rate limiter. For production with multiple instances, use IDistributedCache.
/// </summary>
internal sealed class RateLimitService(IOptions<RateLimitOptions> optionsAccessor) : IRateLimitService
{
    private readonly RateLimitOptions _options = optionsAccessor.Value;
    private readonly Dictionary<string, (int count, DateTime resetTime)> _ipAttempts = new();
    private readonly Dictionary<string, (int count, DateTime resetTime)> _emailAttempts = new();
    private readonly object _lockObj = new();

    public bool IsAllowedByIp(string ipAddress, string operation = "auth")
    {
        if (!_options.Enabled)
            return true;

        lock (_lockObj)
        {
            var key = $"{operation}:{ipAddress}";
            if (_ipAttempts.TryGetValue(key, out var attempt))
            {
                if (DateTime.UtcNow < attempt.resetTime && attempt.count >= _options.MaxAttemptsPerIpPerMinute)
                    return false;

                if (DateTime.UtcNow >= attempt.resetTime)
                    _ipAttempts.Remove(key);
            }

            return true;
        }
    }

    public bool IsAllowedByEmail(string email, string operation = "auth")
    {
        if (!_options.Enabled)
            return true;

        lock (_lockObj)
        {
            var key = $"{operation}:{email.ToLowerInvariant()}";
            if (_emailAttempts.TryGetValue(key, out var attempt))
            {
                if (DateTime.UtcNow < attempt.resetTime && attempt.count >= _options.MaxAttemptsPerEmailPer15Minutes)
                    return false;

                if (DateTime.UtcNow >= attempt.resetTime)
                    _emailAttempts.Remove(key);
            }

            return true;
        }
    }

    public void RecordFailureByIp(string ipAddress, string operation = "auth")
    {
        if (!_options.Enabled)
            return;

        lock (_lockObj)
        {
            var key = $"{operation}:{ipAddress}";
            if (_ipAttempts.TryGetValue(key, out var attempt))
            {
                _ipAttempts[key] = (attempt.count + 1, attempt.resetTime);
            }
            else
            {
                _ipAttempts[key] = (1, DateTime.UtcNow.AddMinutes(1));
            }
        }
    }

    public void RecordFailureByEmail(string email, string operation = "auth")
    {
        if (!_options.Enabled)
            return;

        lock (_lockObj)
        {
            var key = $"{operation}:{email.ToLowerInvariant()}";
            if (_emailAttempts.TryGetValue(key, out var attempt))
            {
                _emailAttempts[key] = (attempt.count + 1, attempt.resetTime);
            }
            else
            {
                _emailAttempts[key] = (1, DateTime.UtcNow.AddMinutes(15));
            }
        }
    }

    public void ResetIp(string ipAddress, string operation = "auth")
    {
        lock (_lockObj)
        {
            var key = $"{operation}:{ipAddress}";
            _ipAttempts.Remove(key);
        }
    }

    public void ResetEmail(string email, string operation = "auth")
    {
        lock (_lockObj)
        {
            var key = $"{operation}:{email.ToLowerInvariant()}";
            _emailAttempts.Remove(key);
        }
    }
}
