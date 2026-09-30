using System.Globalization;

using Microsoft.Extensions.Caching.Distributed;

namespace Aegis.Auth.Features.SecondaryStorage;

/// <summary>
/// Opt-in <see cref="IAegisSecondaryStorage"/> on top of any <see cref="IDistributedCache"/>.
/// <para>
/// <b>Not atomic.</b> <see cref="IDistributedCache"/> has no compare-and-set or increment, so
/// <see cref="IncrementAsync"/> and <see cref="SetIfNotExistsAsync"/> are read-then-write: concurrent callers
/// can lose increments, and more than one caller can "win" <see cref="SetIfNotExistsAsync"/>. Do not rely on it
/// for single-use or replay protection across instances. A warning is logged at startup when it is used.
/// </para>
/// Each value is stored with its absolute expiry prepended (<c>{utcTicks}:{value}</c>) so a counter keeps its
/// original window and expiry follows the injected <see cref="TimeProvider"/>, not the cache's own clock.
/// </summary>
internal sealed class DistributedCacheSecondaryStorage(IDistributedCache cache, TimeProvider timeProvider) : IAegisSecondaryStorage
{
    private static readonly TimeSpan MinimumCacheTtl = TimeSpan.FromSeconds(1);

    public async Task<string?> GetAsync(string key, CancellationToken ct = default)
    {
        SecondaryStorageGuard.ValidateKey(key);
        return (await GetEntryAsync(key, ct).ConfigureAwait(false))?.Value;
    }

    public Task SetAsync(string key, string value, TimeSpan ttl, CancellationToken ct = default)
    {
        SecondaryStorageGuard.ValidateKey(key);
        ArgumentNullException.ThrowIfNull(value);
        SecondaryStorageGuard.ValidateTtl(ttl);

        return WriteAsync(key, value, SecondaryStorageGuard.GetExpiry(timeProvider.GetUtcNow(), ttl), ct);
    }

    public async Task<bool> DeleteAsync(string key, CancellationToken ct = default)
    {
        SecondaryStorageGuard.ValidateKey(key);
        var existed = await GetEntryAsync(key, ct).ConfigureAwait(false) is not null;
        await cache.RemoveAsync(key, ct).ConfigureAwait(false);
        return existed;
    }

    public async Task<long> IncrementAsync(string key, TimeSpan ttl, CancellationToken ct = default)
    {
        SecondaryStorageGuard.ValidateKey(key);
        SecondaryStorageGuard.ValidateTtl(ttl);

        (string Value, DateTimeOffset ExpiresAt)? current = await GetEntryAsync(key, ct).ConfigureAwait(false);
        if (current is null)
        {
            await WriteAsync(key, "1", SecondaryStorageGuard.GetExpiry(timeProvider.GetUtcNow(), ttl), ct).ConfigureAwait(false);
            return 1;
        }

        var next = checked(SecondaryStorageGuard.ParseCounter(key, current.Value.Value) + 1);
        await WriteAsync(key, SecondaryStorageGuard.FormatCounter(next), current.Value.ExpiresAt, ct).ConfigureAwait(false);
        return next;
    }

    public async Task<bool> SetIfNotExistsAsync(string key, string value, TimeSpan ttl, CancellationToken ct = default)
    {
        SecondaryStorageGuard.ValidateKey(key);
        ArgumentNullException.ThrowIfNull(value);
        SecondaryStorageGuard.ValidateTtl(ttl);

        if (await GetEntryAsync(key, ct).ConfigureAwait(false) is not null)
        {
            return false;
        }

        await WriteAsync(key, value, SecondaryStorageGuard.GetExpiry(timeProvider.GetUtcNow(), ttl), ct).ConfigureAwait(false);
        return true;
    }

    private async Task<(string Value, DateTimeOffset ExpiresAt)?> GetEntryAsync(string key, CancellationToken ct)
    {
        var stored = await cache.GetStringAsync(key, ct).ConfigureAwait(false);
        if (stored is null)
        {
            return null;
        }

        var separator = stored.IndexOf(':', StringComparison.Ordinal);
        if (separator <= 0
            || long.TryParse(stored.AsSpan(0, separator), NumberStyles.None, CultureInfo.InvariantCulture, out var ticks) is false
            || ticks > DateTimeOffset.MaxValue.UtcTicks)
        {
            // Not written by this adapter: treat as missing rather than returning foreign data.
            return null;
        }

        var expiresAt = new DateTimeOffset(ticks, TimeSpan.Zero);
        return expiresAt > timeProvider.GetUtcNow() ? (stored[(separator + 1)..], expiresAt) : null;
    }

    private Task WriteAsync(string key, string value, DateTimeOffset expiresAt, CancellationToken ct)
    {
        // Relative expiry: the cache's clock may differ from ours, and an absolute expiry it considers
        // past is rejected. The embedded expiry stays authoritative either way.
        TimeSpan remaining = expiresAt - timeProvider.GetUtcNow();
        return cache.SetStringAsync(
            key,
            string.Create(CultureInfo.InvariantCulture, $"{expiresAt.UtcTicks}:{value}"),
            new DistributedCacheEntryOptions { AbsoluteExpirationRelativeToNow = remaining > MinimumCacheTtl ? remaining : MinimumCacheTtl },
            ct);
    }
}
