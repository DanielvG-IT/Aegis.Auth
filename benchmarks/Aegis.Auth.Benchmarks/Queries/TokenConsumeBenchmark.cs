using Aegis.Auth.Benchmarks.Infrastructure;
using Aegis.Auth.Core.Crypto;
using Aegis.Auth.Entities;

using BenchmarkDotNet.Attributes;

using Dapper;

using Microsoft.EntityFrameworkCore;

namespace Aegis.Auth.Benchmarks.Queries;

/// <summary>
/// Consuming a single-use token (email verification, password reset). <see cref="EfTracked"/> is today's
/// read-check-write; the conditional-update variants are the atomic form AGENTS.md requires (#121).
/// AsNoTracking has no meaning for a write, so the "no tracking" row here is <c>ExecuteUpdate</c>, and the compiled
/// variant compiles the lookup that precedes the tracked write.
/// </summary>
/// <remarks>
/// A consumed token cannot be consumed again, so every invocation takes the next token from a pool of
/// <see cref="PoolSize"/> and each iteration starts with the pool reset. The iteration setup is not measured, and
/// iterations are capped at 30 because each one is a thousand writes.
/// </remarks>
[BenchmarkCategory("Query", "TokenConsume")]
[InvocationCount(PoolSize)]
[MaxIterationCount(30)]
public class TokenConsumeBenchmark
{
    private const int PoolSize = 1_000;
    private const string Purpose = BenchDatabase.EmailVerificationPurpose;

    private static readonly Func<BenchDbContext, string, string, Task<AuthToken?>> CompiledLookup =
        EF.CompileAsyncQuery((BenchDbContext db, string tokenHash, string purpose) =>
            db.AuthTokens.FirstOrDefault(t => t.TokenHash == tokenHash && t.Purpose == purpose));

    private const string Sql = """
        UPDATE "AuthTokens" SET "ConsumedAt" = @now
        WHERE "TokenHash" = @tokenHash AND "Purpose" = @purpose AND "ConsumedAt" IS NULL AND "ExpiresAt" > @now
        """;

    private BenchDatabase _database = null!;
    private string[] _tokenHashes = [];
    private int _next;

    [ParamsSource(typeof(BenchEnvironment), nameof(BenchEnvironment.AvailableProviders))]
    public DatabaseProvider Provider { get; set; }

    [GlobalSetup]
    public async Task Setup()
    {
        _database = await BenchDatabase.CreateAsync(Provider);

        // Spread the pool over the table rather than one hot corner of the index.
        _tokenHashes = [.. Enumerable.Range(0, PoolSize)
            .Select(i => AegisCrypto.HashToken(BenchDatabase.VerificationToken(i * (BenchDatabase.UserCount / PoolSize))))];

        foreach (Func<Task<bool>> variant in new Func<Task<bool>>[] { EfTracked, EfCompiledTracked, EfExecuteUpdate, EfExecuteUpdatePooled, Dapper })
        {
            ResetPool();
            QueryGuard.Expect(await variant(), nameof(TokenConsumeBenchmark));
            QueryGuard.Expect(!await ConsumeAgain(variant), $"{nameof(TokenConsumeBenchmark)} (replay)");
        }
    }

    [IterationSetup]
    public void ResetPool()
    {
        using BenchDbContext db = _database.CreateContext();
        db.AuthTokens.Where(t => t.Purpose == Purpose && t.ConsumedAt != null)
            .ExecuteUpdate(s => s.SetProperty(t => t.ConsumedAt, (DateTime?)null));
        _next = 0;
    }

    [GlobalCleanup]
    public ValueTask Cleanup() => _database.DisposeAsync();

    [Benchmark(Baseline = true)]
    public async Task<bool> EfTracked()
    {
        var tokenHash = _tokenHashes[_next++];
        DateTime now = DateTime.UtcNow;

        await using BenchDbContext db = _database.CreateContext();
        AuthToken? token = await db.AuthTokens.FirstOrDefaultAsync(t => t.TokenHash == tokenHash && t.Purpose == Purpose);
        if (token is null || token.ExpiresAt < now || token.ConsumedAt.HasValue)
        {
            return false;
        }

        token.ConsumedAt = now;
        await db.SaveChangesAsync();
        return true;
    }

    [Benchmark]
    public async Task<bool> EfCompiledTracked()
    {
        var tokenHash = _tokenHashes[_next++];
        DateTime now = DateTime.UtcNow;

        await using BenchDbContext db = _database.CreateContext();
        AuthToken? token = await CompiledLookup(db, tokenHash, Purpose);
        if (token is null || token.ExpiresAt < now || token.ConsumedAt.HasValue)
        {
            return false;
        }

        token.ConsumedAt = now;
        await db.SaveChangesAsync();
        return true;
    }

    [Benchmark]
    public async Task<bool> EfExecuteUpdate()
    {
        var tokenHash = _tokenHashes[_next++];
        DateTime now = DateTime.UtcNow;

        await using BenchDbContext db = _database.CreateContext();
        var affected = await db.AuthTokens
            .Where(t => t.TokenHash == tokenHash && t.Purpose == Purpose && t.ConsumedAt == null && t.ExpiresAt > now)
            .ExecuteUpdateAsync(s => s.SetProperty(t => t.ConsumedAt, now));
        return affected == 1;
    }

    [Benchmark]
    public async Task<bool> EfExecuteUpdatePooled()
    {
        var tokenHash = _tokenHashes[_next++];
        DateTime now = DateTime.UtcNow;

        await using BenchDbContext db = _database.Pool.CreateDbContext();
        var affected = await db.AuthTokens
            .Where(t => t.TokenHash == tokenHash && t.Purpose == Purpose && t.ConsumedAt == null && t.ExpiresAt > now)
            .ExecuteUpdateAsync(s => s.SetProperty(t => t.ConsumedAt, now));
        return affected == 1;
    }

    [Benchmark]
    public async Task<bool> Dapper()
    {
        var tokenHash = _tokenHashes[_next++];
        DateTime now = DateTime.UtcNow;

        await using System.Data.Common.DbConnection connection = _database.CreateConnection();
        var affected = await connection.ExecuteAsync(Sql, new { now, tokenHash, purpose = Purpose });
        return affected == 1;
    }

    private async Task<bool> ConsumeAgain(Func<Task<bool>> variant)
    {
        _next = 0;
        return await variant();
    }
}
