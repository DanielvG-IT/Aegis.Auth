namespace Aegis.Auth.Features.SecondaryStorage;

/// <summary>
/// Short-lived key/value storage with a TTL on every entry, for high-churn state such as challenges,
/// single-use request IDs, attempt counters and caches. Build keys with <see cref="AegisStorageKey.Create"/>.
/// </summary>
/// <remarks>
/// Values are stored as given. Never store a raw secret (token, code, password) as a key or value;
/// store its SHA-256 hash instead.
/// Keys are at most <see cref="AegisStorageKey.MaxLength"/> characters and TTLs must be positive.
/// </remarks>
public interface IAegisSecondaryStorage
{
    /// <summary>Returns the value, or <see langword="null"/> when the key is missing or expired.</summary>
    Task<string?> GetAsync(string key, CancellationToken ct = default);

    /// <summary>Stores the value, replacing any existing value and expiry.</summary>
    Task SetAsync(string key, string value, TimeSpan ttl, CancellationToken ct = default);

    /// <summary>Removes the key. Returns <see langword="true"/> when an unexpired entry was removed.</summary>
    Task<bool> DeleteAsync(string key, CancellationToken ct = default);

    /// <summary>
    /// Atomically increments an integer counter and returns the new value. A missing or expired key
    /// starts at 1 and expires after <paramref name="ttl"/>; incrementing an existing counter keeps its
    /// original expiry (a fixed window). Throws <see cref="InvalidOperationException"/> when the stored
    /// value is not an integer.
    /// </summary>
    Task<long> IncrementAsync(string key, TimeSpan ttl, CancellationToken ct = default);

    /// <summary>
    /// Atomically stores the value only when the key is missing or expired. Returns <see langword="true"/>
    /// for exactly one of any number of concurrent callers; use it for single-use and replay protection.
    /// </summary>
    Task<bool> SetIfNotExistsAsync(string key, string value, TimeSpan ttl, CancellationToken ct = default);
}
