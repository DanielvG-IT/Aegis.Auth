using Aegis.Auth.Abstractions;

using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Storage;

namespace Aegis.Auth.Infrastructure.Tokens;

/// <summary>
/// Redeems single-use <see cref="Entities.AuthToken"/>s. Every single-use flow must go through this,
/// never read-check-write on <c>ConsumedAt</c>, so parallel requests with one token cannot both win.
/// </summary>
internal interface IAuthTokenStore
{
    /// <summary>
    /// Atomically marks an unexpired, unconsumed token as consumed and, only if this call won,
    /// runs <paramref name="onConsumed"/> for the dependent writes. On relational providers both
    /// happen in one transaction, so a failing <paramref name="onConsumed"/> leaves the token unused.
    /// </summary>
    /// <remarks>
    /// <paramref name="onConsumed"/> may run again when a retrying execution strategy replays the
    /// transaction, so write through <c>ExecuteUpdateAsync</c> rather than tracked entities.
    /// </remarks>
    /// <returns><c>true</c> for the one caller that consumed the token; <c>false</c> when it is unknown, expired or already used.</returns>
    Task<bool> TryConsumeAsync(string tokenHash, string purpose, Func<CancellationToken, Task> onConsumed, CancellationToken ct = default);
}

internal sealed class AuthTokenStore(IAuthDbContext dbContext) : IAuthTokenStore
{
    private readonly IAuthDbContext _db = dbContext;

    public async Task<bool> TryConsumeAsync(string tokenHash, string purpose, Func<CancellationToken, Task> onConsumed, CancellationToken ct = default)
    {
        DatabaseFacade? database = (_db as DbContext)?.Database;

        // Join the caller's transaction if there is one. Non-relational providers have no transactions.
        if (database is null || database.IsRelational() is false || database.CurrentTransaction is not null)
            return await ConsumeAndApplyAsync(tokenHash, purpose, onConsumed, ct);

        IExecutionStrategy strategy = database.CreateExecutionStrategy();
        return await strategy.ExecuteAsync(async cancellationToken =>
        {
            await using IDbContextTransaction transaction = await database.BeginTransactionAsync(cancellationToken);
            if (await ConsumeAndApplyAsync(tokenHash, purpose, onConsumed, cancellationToken) is false)
                return false;

            await transaction.CommitAsync(cancellationToken);
            return true;
        }, ct);
    }

    private async Task<bool> ConsumeAndApplyAsync(string tokenHash, string purpose, Func<CancellationToken, Task> onConsumed, CancellationToken ct)
    {
        var now = DateTime.UtcNow;
        var consumed = await _db.AuthTokens
            .Where(t => t.TokenHash == tokenHash && t.Purpose == purpose && t.ConsumedAt == null && t.ExpiresAt > now)
            .ExecuteUpdateAsync(s => s.SetProperty(t => t.ConsumedAt, now), ct);

        if (consumed == 0)
            return false;

        await onConsumed(ct);
        return true;
    }
}
