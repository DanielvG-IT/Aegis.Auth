using Aegis.Auth.Abstractions;
using Aegis.Auth.Entities;
using Aegis.Auth.Logging;

using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace Aegis.Auth.Features.SecondaryStorage;

/// <summary>
/// Opt-in <see cref="IAegisSecondaryStorage"/> on the <see cref="AegisKeyValue"/> table, for multi-instance
/// deployments without Redis. Atomicity comes from the database: inserts race on the primary key (exactly
/// one wins) and increments are conditional updates on the value that was read (compare-and-swap, retried).
/// <para>
/// Registered as a singleton; every attempt runs in its own DI scope, so it never flushes or observes
/// the caller's tracked changes. Requires a relational provider (<c>ExecuteUpdate</c>/<c>ExecuteDelete</c>).
/// Expired rows are ignored and purged at most once per <see cref="SweepInterval"/>, triggered by writes.
/// </para>
/// </summary>
internal sealed class DatabaseSecondaryStorage(IServiceScopeFactory scopeFactory, TimeProvider timeProvider, ILoggerFactory loggerFactory) : IAegisSecondaryStorage
{
    internal static readonly TimeSpan SweepInterval = TimeSpan.FromMinutes(5);

    private readonly ILogger _logger = loggerFactory.CreateLogger<DatabaseSecondaryStorage>();
    private long _nextSweepTicks = timeProvider.GetUtcNow().Add(SweepInterval).UtcTicks;
    private int _sweeping;

    public async Task<string?> GetAsync(string key, CancellationToken ct = default)
    {
        SecondaryStorageGuard.ValidateKey(key);
        DateTime now = UtcNow();

        await using AsyncServiceScope scope = scopeFactory.CreateAsyncScope();
        return await Db(scope).AegisKeyValues.AsNoTracking()
            .Where(e => e.Key == key && e.ExpiresAt > now)
            .Select(e => e.Value)
            .FirstOrDefaultAsync(ct)
            .ConfigureAwait(false);
    }

    public async Task SetAsync(string key, string value, TimeSpan ttl, CancellationToken ct = default)
    {
        SecondaryStorageGuard.ValidateKey(key);
        ArgumentNullException.ThrowIfNull(value);
        SecondaryStorageGuard.ValidateTtl(ttl);
        DateTime now = UtcNow();
        DateTime expiresAt = ExpiryFrom(now, ttl);

        while (true)
        {
            ct.ThrowIfCancellationRequested();
            await using AsyncServiceScope scope = scopeFactory.CreateAsyncScope();
            IAuthDbContext db = Db(scope);

            var updated = await db.AegisKeyValues
                .Where(e => e.Key == key)
                .ExecuteUpdateAsync(s => s.SetProperty(e => e.Value, value).SetProperty(e => e.ExpiresAt, expiresAt), ct)
                .ConfigureAwait(false);
            if (updated > 0 || await TryInsertAsync(db, key, value, expiresAt, ct).ConfigureAwait(false))
            {
                break;
            }

            // Another caller inserted the key between our update and insert: update it on the next pass.
        }

        await SweepIfDueAsync(now, ct).ConfigureAwait(false);
    }

    public async Task<bool> DeleteAsync(string key, CancellationToken ct = default)
    {
        SecondaryStorageGuard.ValidateKey(key);
        DateTime now = UtcNow();

        await using AsyncServiceScope scope = scopeFactory.CreateAsyncScope();
        var deleted = await Db(scope).AegisKeyValues
            .Where(e => e.Key == key && e.ExpiresAt > now)
            .ExecuteDeleteAsync(ct)
            .ConfigureAwait(false);
        return deleted > 0;
    }

    public async Task<long> IncrementAsync(string key, TimeSpan ttl, CancellationToken ct = default)
    {
        SecondaryStorageGuard.ValidateKey(key);
        SecondaryStorageGuard.ValidateTtl(ttl);
        DateTime now = UtcNow();

        while (true)
        {
            ct.ThrowIfCancellationRequested();
            await using AsyncServiceScope scope = scopeFactory.CreateAsyncScope();
            IAuthDbContext db = Db(scope);

            var current = await db.AegisKeyValues.AsNoTracking()
                .Where(e => e.Key == key && e.ExpiresAt > now)
                .Select(e => e.Value)
                .FirstOrDefaultAsync(ct)
                .ConfigureAwait(false);

            if (current is not null)
            {
                var next = checked(SecondaryStorageGuard.ParseCounter(key, current) + 1);
                var nextValue = SecondaryStorageGuard.FormatCounter(next);
                // Compare-and-swap on the value we read; the expiry is left alone (fixed window).
                var swapped = await db.AegisKeyValues
                    .Where(e => e.Key == key && e.Value == current && e.ExpiresAt > now)
                    .ExecuteUpdateAsync(s => s.SetProperty(e => e.Value, nextValue), ct)
                    .ConfigureAwait(false);
                if (swapped > 0)
                {
                    return next;
                }

                continue;
            }

            await DeleteExpiredAsync(db, key, now, ct).ConfigureAwait(false);
            if (await TryInsertAsync(db, key, "1", ExpiryFrom(now, ttl), ct).ConfigureAwait(false))
            {
                await SweepIfDueAsync(now, ct).ConfigureAwait(false);
                return 1;
            }
        }
    }

    public async Task<bool> SetIfNotExistsAsync(string key, string value, TimeSpan ttl, CancellationToken ct = default)
    {
        SecondaryStorageGuard.ValidateKey(key);
        ArgumentNullException.ThrowIfNull(value);
        SecondaryStorageGuard.ValidateTtl(ttl);
        DateTime now = UtcNow();

        await using AsyncServiceScope scope = scopeFactory.CreateAsyncScope();
        IAuthDbContext db = Db(scope);

        // An expired row still occupies the key; remove it so the insert below can win. Only expired rows
        // match, so a live entry written concurrently is never deleted.
        await DeleteExpiredAsync(db, key, now, ct).ConfigureAwait(false);
        var inserted = await TryInsertAsync(db, key, value, ExpiryFrom(now, ttl), ct).ConfigureAwait(false);
        if (inserted)
        {
            await SweepIfDueAsync(now, ct).ConfigureAwait(false);
        }

        return inserted;
    }

    /// <summary>
    /// Inserts the row and returns <see langword="false"/> when the key already exists (primary key conflict).
    /// Any other failure is rethrown.
    /// </summary>
    private async Task<bool> TryInsertAsync(IAuthDbContext db, string key, string value, DateTime expiresAt, CancellationToken ct)
    {
        db.AegisKeyValues.Add(new AegisKeyValue { Key = key, Value = value, ExpiresAt = expiresAt });
        try
        {
            await db.SaveChangesAsync(ct).ConfigureAwait(false);
            return true;
        }
        catch (DbUpdateException)
        {
            // Provider-agnostic conflict detection: the insert lost only if the key now exists.
            await using AsyncServiceScope checkScope = scopeFactory.CreateAsyncScope();
            if (await Db(checkScope).AegisKeyValues.AsNoTracking().AnyAsync(e => e.Key == key, ct).ConfigureAwait(false))
            {
                return false;
            }

            throw;
        }
    }

    private static Task<int> DeleteExpiredAsync(IAuthDbContext db, string key, DateTime now, CancellationToken ct) =>
        db.AegisKeyValues.Where(e => e.Key == key && e.ExpiresAt <= now).ExecuteDeleteAsync(ct);

    private async Task SweepIfDueAsync(DateTime now, CancellationToken ct)
    {
        if (now.Ticks < Interlocked.Read(ref _nextSweepTicks) || Interlocked.Exchange(ref _sweeping, 1) == 1)
        {
            return;
        }

        try
        {
            Interlocked.Exchange(ref _nextSweepTicks, now.Add(SweepInterval).Ticks);
            await using AsyncServiceScope scope = scopeFactory.CreateAsyncScope();
            var removed = await Db(scope).AegisKeyValues.Where(e => e.ExpiresAt <= now).ExecuteDeleteAsync(ct).ConfigureAwait(false);
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

    private DateTime UtcNow() => timeProvider.GetUtcNow().UtcDateTime;

    private static DateTime ExpiryFrom(DateTime now, TimeSpan ttl) =>
        SecondaryStorageGuard.GetExpiry(new DateTimeOffset(now, TimeSpan.Zero), ttl).UtcDateTime;

    private static IAuthDbContext Db(AsyncServiceScope scope) => scope.ServiceProvider.GetRequiredService<IAuthDbContext>();
}
