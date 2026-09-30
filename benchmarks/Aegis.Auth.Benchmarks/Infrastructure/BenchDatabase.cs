using Aegis.Auth.Core.Crypto;
using Aegis.Auth.Entities;

using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;

using Npgsql;

namespace Aegis.Auth.Benchmarks.Infrastructure;

/// <summary>
/// A throwaway database with the Aegis schema and a deterministic data set, so every run and every
/// variant queries the same rows. One instance per benchmark case; <see cref="DisposeAsync"/> drops it.
/// </summary>
public sealed class BenchDatabase : IAsyncDisposable
{
    /// <summary>Rows per table. Large enough that a missing index would show up.</summary>
    public const int UserCount = 10_000;

    public const string EmailVerificationPurpose = "email-verification";
    public const string Password = "correct horse battery staple";

    private readonly string? _sqliteFile;
    private readonly string? _postgresDatabase;
    private readonly string? _postgresAdminConnectionString;

    public DatabaseProvider Provider { get; }
    public string ConnectionString { get; }
    public DbContextOptions<BenchDbContext> Options { get; }

    /// <summary>What <c>AddDbContextPool</c> registers: contexts are reset and reused instead of built per request.</summary>
    public PooledDbContextFactory<BenchDbContext> Pool { get; }

    private BenchDatabase(DatabaseProvider provider, string connectionString, string? sqliteFile, string? postgresDatabase, string? postgresAdminConnectionString)
    {
        Provider = provider;
        ConnectionString = connectionString;
        _sqliteFile = sqliteFile;
        _postgresDatabase = postgresDatabase;
        _postgresAdminConnectionString = postgresAdminConnectionString;

        var builder = new DbContextOptionsBuilder<BenchDbContext>();
        Configure(builder);
        Options = builder.Options;
        Pool = new PooledDbContextFactory<BenchDbContext>(Options);
    }

    /// <summary>Creates the schema and seeds <see cref="UserCount"/> users with an account, a session and a token each.</summary>
    public static async Task<BenchDatabase> CreateAsync(DatabaseProvider provider, string? passwordHash = null)
    {
        BenchDatabase database;
        switch (provider)
        {
            case DatabaseProvider.Sqlite:
                var file = Path.Combine(Path.GetTempPath(), $"aegis-bench-{Guid.NewGuid():N}.db");
                database = new BenchDatabase(provider, $"Data Source={file};Pooling=True", file, null, null);
                break;

            case DatabaseProvider.Postgres:
                var adminConnectionString = BenchEnvironment.PostgresConnectionString
                    ?? throw new InvalidOperationException($"PostgreSQL is not configured. Run with --postgres or set {BenchEnvironment.PostgresVariable}.");
                var databaseName = $"aegis_bench_{Guid.NewGuid():N}";
                var connectionString = new NpgsqlConnectionStringBuilder(adminConnectionString) { Database = databaseName }.ConnectionString;
                database = new BenchDatabase(provider, connectionString, null, databaseName, adminConnectionString);
                break;

            default:
                throw new ArgumentOutOfRangeException(nameof(provider), provider, null);
        }

        await database.InitializeAsync(passwordHash ?? "not-a-real-hash");
        return database;
    }

    public void Configure(DbContextOptionsBuilder builder)
    {
        _ = Provider switch
        {
            DatabaseProvider.Sqlite => builder.UseSqlite(ConnectionString),
            DatabaseProvider.Postgres => builder.UseNpgsql(ConnectionString),
            _ => throw new ArgumentOutOfRangeException(nameof(Provider)),
        };
    }

    public BenchDbContext CreateContext() => new(Options);

    public System.Data.Common.DbConnection CreateConnection() => Provider switch
    {
        DatabaseProvider.Sqlite => new SqliteConnection(ConnectionString),
        DatabaseProvider.Postgres => new NpgsqlConnection(ConnectionString),
        _ => throw new ArgumentOutOfRangeException(nameof(Provider)),
    };

    // ── Deterministic data ───────────────────────────────────────────────────

    public static string UserId(int i) => $"user-{i:D6}";
    public static string Email(int i) => $"user{i:D6}@bench.aegis.local";
    public static string SessionToken(int i) => $"session-token-{i:D6}-aaaaaaaaaaaaaaaa";
    public static string VerificationToken(int i) => $"verify-token-{i:D6}-bbbbbbbbbbbbbbbb";

    /// <summary>A row in the middle of the table, so neither end of the index is favoured.</summary>
    public const int TargetIndex = UserCount / 2;

    private async Task InitializeAsync(string passwordHash)
    {
        await using (BenchDbContext db = CreateContext())
        {
            await db.Database.EnsureCreatedAsync();

            if (Provider is DatabaseProvider.Sqlite)
            {
                // WAL is what a production SQLite deployment runs; the default rollback journal fsyncs twice per write.
                await db.Database.ExecuteSqlRawAsync("PRAGMA journal_mode=WAL;");
            }
        }

        DateTime now = DateTime.UtcNow;
        const int batchSize = 1_000;
        for (var start = 0; start < UserCount; start += batchSize)
        {
            await using BenchDbContext db = CreateContext();
            db.ChangeTracker.AutoDetectChangesEnabled = false;

            for (var i = start; i < Math.Min(start + batchSize, UserCount); i++)
            {
                var userId = UserId(i);
                db.Users.Add(new User
                {
                    Id = userId,
                    Name = $"Bench User {i}",
                    Email = Email(i),
                    EmailVerified = true,
                    CreatedAt = now,
                    UpdatedAt = now,
                });
                db.Accounts.Add(new Account
                {
                    Id = $"account-{i:D6}",
                    AccountId = userId,
                    ProviderId = "credential",
                    PasswordHash = passwordHash,
                    UserId = userId,
                    CreatedAt = now,
                    UpdatedAt = now,
                });
                db.Sessions.Add(new Session
                {
                    Id = $"session-{i:D6}",
                    TokenHash = AegisCrypto.HashToken(SessionToken(i)),
                    ExpiresAt = now.AddDays(7),
                    IpAddress = "203.0.113.10",
                    UserAgent = "Aegis.Auth.Benchmarks",
                    UserId = userId,
                    CreatedAt = now,
                    UpdatedAt = now,
                });
                db.AuthTokens.Add(new AuthToken
                {
                    Id = $"token-{i:D6}",
                    TokenHash = AegisCrypto.HashToken(VerificationToken(i)),
                    Purpose = EmailVerificationPurpose,
                    ExpiresAt = now.AddDays(1),
                    UserId = userId,
                    CreatedAt = now,
                });
            }

            await db.SaveChangesAsync();
        }

        // Fresh statistics so the planner sees the real table sizes, as it would in production.
        await using (BenchDbContext db = CreateContext())
        {
            await db.Database.ExecuteSqlRawAsync("ANALYZE;");
        }
    }

    public async ValueTask DisposeAsync()
    {
        switch (Provider)
        {
            case DatabaseProvider.Sqlite:
                SqliteConnection.ClearAllPools();
                foreach (var suffix in new[] { "", "-wal", "-shm" })
                {
                    File.Delete(_sqliteFile + suffix);
                }
                break;

            case DatabaseProvider.Postgres:
                NpgsqlConnection.ClearAllPools();
                await using (var admin = new NpgsqlConnection(_postgresAdminConnectionString))
                {
                    await admin.OpenAsync();
                    await using NpgsqlCommand drop = admin.CreateCommand();
                    drop.CommandText = $"DROP DATABASE IF EXISTS \"{_postgresDatabase}\" WITH (FORCE)";
                    await drop.ExecuteNonQueryAsync();
                }
                break;
        }
    }
}
