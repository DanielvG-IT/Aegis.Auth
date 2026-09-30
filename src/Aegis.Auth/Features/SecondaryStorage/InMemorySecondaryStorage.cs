using System.Collections.Concurrent;

using Aegis.Auth.Logging;

using Microsoft.Extensions.Logging;

namespace Aegis.Auth.Features.SecondaryStorage;

/// <summary>
/// Default <see cref="IAegisSecondaryStorage"/>: a per-process dictionary. Every operation is atomic
/// (lock-free compare-and-swap on immutable entries). Expired entries are invisible immediately and are
/// removed by a sweep that runs at most once per <see cref="SweepInterval"/>, triggered by writes, so
/// memory stays bounded by the entries written in the last interval plus those still alive.
/// State is not shared between instances; use the database or a Redis implementation for that.
/// </summary>
internal sealed class InMemorySecondaryStorage(TimeProvider timeProvider, ILoggerFactory loggerFactory) : IAegisSecondaryStorage
{
    internal static readonly TimeSpan SweepInterval = TimeSpan.FromMinutes(1);

    private readonly ConcurrentDictionary<string, Entry> _entries = new(StringComparer.Ordinal);
    private readonly ILogger _logger = loggerFactory.CreateLogger<InMemorySecondaryStorage>();
    private long _nextSweepTicks = timeProvider.GetUtcNow().Add(SweepInterval).UtcTicks;
    private int _sweeping;

    internal int Count => _entries.Count;

    public Task<string?> GetAsync(string key, CancellationToken ct = default)
    {
        SecondaryStorageGuard.ValidateKey(key);
        DateTimeOffset now = timeProvider.GetUtcNow();
        return Task.FromResult(_entries.TryGetValue(key, out Entry? entry) && entry.IsAlive(now) ? entry.Value : null);
    }

    public Task SetAsync(string key, string value, TimeSpan ttl, CancellationToken ct = default)
    {
        SecondaryStorageGuard.ValidateKey(key);
        ArgumentNullException.ThrowIfNull(value);
        SecondaryStorageGuard.ValidateTtl(ttl);

        DateTimeOffset now = timeProvider.GetUtcNow();
        _entries[key] = new Entry(value, SecondaryStorageGuard.GetExpiry(now, ttl));
        SweepIfDue(now);
        return Task.CompletedTask;
    }

    public Task<bool> DeleteAsync(string key, CancellationToken ct = default)
    {
        SecondaryStorageGuard.ValidateKey(key);
        DateTimeOffset now = timeProvider.GetUtcNow();
        return Task.FromResult(_entries.TryRemove(key, out Entry? removed) && removed.IsAlive(now));
    }

    public Task<long> IncrementAsync(string key, TimeSpan ttl, CancellationToken ct = default)
    {
        SecondaryStorageGuard.ValidateKey(key);
        SecondaryStorageGuard.ValidateTtl(ttl);

        DateTimeOffset now = timeProvider.GetUtcNow();
        while (true)
        {
            if (_entries.TryGetValue(key, out Entry? current) && current.IsAlive(now))
            {
                var next = checked(SecondaryStorageGuard.ParseCounter(key, current.Value) + 1);
                // Keep the original expiry: the counter is a fixed window.
                if (_entries.TryUpdate(key, new Entry(SecondaryStorageGuard.FormatCounter(next), current.ExpiresAt), current))
                {
                    return Task.FromResult(next);
                }

                continue;
            }

            if (TryReplaceMissingOrExpired(key, current, new Entry("1", SecondaryStorageGuard.GetExpiry(now, ttl))))
            {
                SweepIfDue(now);
                return Task.FromResult(1L);
            }
        }
    }

    public Task<bool> SetIfNotExistsAsync(string key, string value, TimeSpan ttl, CancellationToken ct = default)
    {
        SecondaryStorageGuard.ValidateKey(key);
        ArgumentNullException.ThrowIfNull(value);
        SecondaryStorageGuard.ValidateTtl(ttl);

        DateTimeOffset now = timeProvider.GetUtcNow();
        var candidate = new Entry(value, SecondaryStorageGuard.GetExpiry(now, ttl));
        while (true)
        {
            if (_entries.TryGetValue(key, out Entry? current) && current.IsAlive(now))
            {
                return Task.FromResult(false);
            }

            if (TryReplaceMissingOrExpired(key, current, candidate))
            {
                SweepIfDue(now);
                return Task.FromResult(true);
            }
        }
    }

    /// <summary>
    /// Compare-and-swap: adds when <paramref name="expected"/> is null, otherwise replaces it only if it is
    /// still the stored entry. Fails when another caller changed the key first, so the caller retries.
    /// </summary>
    private bool TryReplaceMissingOrExpired(string key, Entry? expected, Entry replacement) =>
        expected is null
            ? _entries.TryAdd(key, replacement)
            : _entries.TryUpdate(key, replacement, expected);

    private void SweepIfDue(DateTimeOffset now)
    {
        if (now.UtcTicks < Interlocked.Read(ref _nextSweepTicks) || Interlocked.Exchange(ref _sweeping, 1) == 1)
        {
            return;
        }

        try
        {
            Interlocked.Exchange(ref _nextSweepTicks, now.Add(SweepInterval).UtcTicks);
            var removed = 0;
            foreach (KeyValuePair<string, Entry> pair in _entries)
            {
                // Removes the pair only if it is unchanged, so a concurrent write is never lost.
                if (pair.Value.IsAlive(now) is false && _entries.TryRemove(pair))
                {
                    removed++;
                }
            }

            if (removed > 0)
            {
                _logger.SecondaryStorageExpiredEntriesPurged(removed);
            }
        }
        finally
        {
            Volatile.Write(ref _sweeping, 0);
        }
    }

    /// <summary>Immutable, compared by reference so compare-and-swap detects every concurrent write.</summary>
    private sealed class Entry(string value, DateTimeOffset expiresAt)
    {
        public string Value { get; } = value;
        public DateTimeOffset ExpiresAt { get; } = expiresAt;

        public bool IsAlive(DateTimeOffset now) => ExpiresAt > now;
    }
}
