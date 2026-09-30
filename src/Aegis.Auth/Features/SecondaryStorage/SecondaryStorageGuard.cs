using System.Globalization;

namespace Aegis.Auth.Features.SecondaryStorage;

/// <summary>
/// Argument checks and helpers shared by every implementation, so they all accept the same input.
/// </summary>
internal static class SecondaryStorageGuard
{
    internal static void ValidateKey(string key)
    {
        ArgumentException.ThrowIfNullOrEmpty(key);
        if (key.Length > AegisStorageKey.MaxLength)
        {
            throw new ArgumentException($"Secondary storage keys are limited to {AegisStorageKey.MaxLength} characters.", nameof(key));
        }
    }

    internal static void ValidateTtl(TimeSpan ttl) =>
        ArgumentOutOfRangeException.ThrowIfLessThanOrEqual(ttl, TimeSpan.Zero);

    internal static DateTimeOffset GetExpiry(DateTimeOffset now, TimeSpan ttl) =>
        ttl >= DateTimeOffset.MaxValue - now ? DateTimeOffset.MaxValue : now + ttl;

    internal static long ParseCounter(string key, string value) =>
        long.TryParse(value, NumberStyles.AllowLeadingSign, CultureInfo.InvariantCulture, out var counter)
            ? counter
            : throw new InvalidOperationException($"The value stored under '{key}' is not an integer counter.");

    internal static string FormatCounter(long value) => value.ToString(CultureInfo.InvariantCulture);
}
