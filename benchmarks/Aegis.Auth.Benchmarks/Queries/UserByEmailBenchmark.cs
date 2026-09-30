using Aegis.Auth.Benchmarks.Infrastructure;
using Aegis.Auth.Entities;

using BenchmarkDotNet.Attributes;

using Dapper;

using Microsoft.EntityFrameworkCore;

namespace Aegis.Auth.Benchmarks.Queries;

/// <summary>
/// The sign-in lookup: the user by normalized email plus their credential account (<c>SignInService</c>,
/// tracked today because a failed attempt updates the lockout counters on the same entity).
/// </summary>
[BenchmarkCategory("Query", "UserByEmail")]
public class UserByEmailBenchmark
{
    private static readonly Func<BenchDbContext, string, Task<User?>> CompiledQuery =
        EF.CompileAsyncQuery((BenchDbContext db, string email) =>
            db.Users.AsNoTracking()
                .Include(u => u.Accounts.Where(a => a.ProviderId == "credential"))
                .FirstOrDefault(u => u.Email == email));

    // One round trip, like EF's single-query include. Account columns are listed so the split on "Id" lands on Account.Id.
    private const string Sql = """
        SELECT u."Id", u."Name", u."Email", u."EmailVerified", u."Image", u."CreatedAt", u."UpdatedAt", u."FailedSignInCount", u."LockoutUntil",
               a."Id", a."AccountId", a."ProviderId", a."PasswordHash", a."UserId", a."CreatedAt", a."UpdatedAt"
        FROM "Users" u
        LEFT JOIN "Accounts" a ON a."UserId" = u."Id" AND a."ProviderId" = 'credential'
        WHERE u."Email" = @email
        """;

    private BenchDatabase _database = null!;
    private string _email = string.Empty;

    [ParamsSource(typeof(BenchEnvironment), nameof(BenchEnvironment.AvailableProviders))]
    public DatabaseProvider Provider { get; set; }

    [GlobalSetup]
    public async Task Setup()
    {
        _database = await BenchDatabase.CreateAsync(Provider);
        _email = BenchDatabase.Email(BenchDatabase.TargetIndex);

        var expected = BenchDatabase.UserId(BenchDatabase.TargetIndex);
        foreach (User? found in new[] { await EfTracked(), await EfNoTracking(), await EfCompiled(), await EfCompiledPooled(), await Dapper() })
        {
            QueryGuard.Expect(found?.Id == expected && found.Accounts.Count == 1 && found.Accounts.First().ProviderId == "credential", nameof(UserByEmailBenchmark));
        }
    }

    [GlobalCleanup]
    public ValueTask Cleanup() => _database.DisposeAsync();

    [Benchmark(Baseline = true)]
    public async Task<User?> EfTracked()
    {
        await using BenchDbContext db = _database.CreateContext();
        return await db.Users
            .Include(u => u.Accounts.Where(a => a.ProviderId == "credential"))
            .FirstOrDefaultAsync(u => u.Email == _email);
    }

    [Benchmark]
    public async Task<User?> EfNoTracking()
    {
        await using BenchDbContext db = _database.CreateContext();
        return await db.Users.AsNoTracking()
            .Include(u => u.Accounts.Where(a => a.ProviderId == "credential"))
            .FirstOrDefaultAsync(u => u.Email == _email);
    }

    [Benchmark]
    public async Task<User?> EfCompiled()
    {
        await using BenchDbContext db = _database.CreateContext();
        return await CompiledQuery(db, _email);
    }

    [Benchmark]
    public async Task<User?> EfCompiledPooled()
    {
        await using BenchDbContext db = _database.Pool.CreateDbContext();
        return await CompiledQuery(db, _email);
    }

    [Benchmark]
    public async Task<User?> Dapper()
    {
        await using System.Data.Common.DbConnection connection = _database.CreateConnection();
        IEnumerable<User> rows = await connection.QueryAsync<User, Account?, User>(
            Sql,
            (user, account) =>
            {
                if (account is not null)
                {
                    user.Accounts.Add(account);
                }

                return user;
            },
            new { email = _email },
            splitOn: "Id");
        return rows.FirstOrDefault();
    }
}
