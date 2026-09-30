using Aegis.Auth.Benchmarks.Infrastructure;
using Aegis.Auth.Core.Crypto;
using Aegis.Auth.Entities;

using BenchmarkDotNet.Attributes;

using Dapper;

using Microsoft.EntityFrameworkCore;

namespace Aegis.Auth.Benchmarks.Queries;

/// <summary>
/// The lookup behind every authenticated request that misses the cookie cache
/// (<c>AegisAuthContextAccessor</c>, which uses the AsNoTracking variant today).
/// Each call opens its own context (or connection) as a request scope would; <c>EfCompiledPooled</c> takes it from an
/// <c>AddDbContextPool</c>-style pool instead, separating context construction from query cost.
/// </summary>
[BenchmarkCategory("Query", "SessionByTokenHash")]
public class SessionByTokenHashBenchmark
{
    private static readonly Func<BenchDbContext, string, Task<Session?>> CompiledQuery =
        EF.CompileAsyncQuery((BenchDbContext db, string tokenHash) =>
            db.Sessions.AsNoTracking().FirstOrDefault(s => s.TokenHash == tokenHash));

    private const string Sql = """
        SELECT "Id", "TokenHash", "ExpiresAt", "IpAddress", "UserAgent", "CreatedAt", "UpdatedAt", "UserId"
        FROM "Sessions"
        WHERE "TokenHash" = @tokenHash
        LIMIT 1
        """;

    private BenchDatabase _database = null!;
    private string _tokenHash = string.Empty;

    [ParamsSource(typeof(BenchEnvironment), nameof(BenchEnvironment.AvailableProviders))]
    public DatabaseProvider Provider { get; set; }

    [GlobalSetup]
    public async Task Setup()
    {
        _database = await BenchDatabase.CreateAsync(Provider);
        _tokenHash = AegisCrypto.HashToken(BenchDatabase.SessionToken(BenchDatabase.TargetIndex));

        var expected = $"session-{BenchDatabase.TargetIndex:D6}";
        foreach (Session? found in new[] { await EfTracked(), await EfNoTracking(), await EfCompiled(), await EfCompiledPooled(), await Dapper() })
        {
            QueryGuard.Expect(found?.Id == expected && found.UserId == BenchDatabase.UserId(BenchDatabase.TargetIndex), nameof(SessionByTokenHashBenchmark));
        }
    }

    [GlobalCleanup]
    public ValueTask Cleanup() => _database.DisposeAsync();

    [Benchmark(Baseline = true)]
    public async Task<Session?> EfTracked()
    {
        await using BenchDbContext db = _database.CreateContext();
        return await db.Sessions.FirstOrDefaultAsync(s => s.TokenHash == _tokenHash);
    }

    [Benchmark]
    public async Task<Session?> EfNoTracking()
    {
        await using BenchDbContext db = _database.CreateContext();
        return await db.Sessions.AsNoTracking().FirstOrDefaultAsync(s => s.TokenHash == _tokenHash);
    }

    [Benchmark]
    public async Task<Session?> EfCompiled()
    {
        await using BenchDbContext db = _database.CreateContext();
        return await CompiledQuery(db, _tokenHash);
    }

    [Benchmark]
    public async Task<Session?> EfCompiledPooled()
    {
        await using BenchDbContext db = _database.Pool.CreateDbContext();
        return await CompiledQuery(db, _tokenHash);
    }

    [Benchmark]
    public async Task<Session?> Dapper()
    {
        await using System.Data.Common.DbConnection connection = _database.CreateConnection();
        return await connection.QueryFirstOrDefaultAsync<Session>(Sql, new { tokenHash = _tokenHash });
    }
}
