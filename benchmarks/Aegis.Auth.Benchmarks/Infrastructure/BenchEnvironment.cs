namespace Aegis.Auth.Benchmarks.Infrastructure;

/// <summary>
/// Which databases this run can reach. BenchmarkDotNet runs every benchmark in a child process that
/// inherits the host's environment, so the PostgreSQL connection string travels as an environment variable.
/// </summary>
public static class BenchEnvironment
{
    /// <summary>
    /// Connection string of a PostgreSQL server the benchmarks may create and drop databases on.
    /// Set by <c>--postgres</c> (Testcontainers) or by hand to use an existing server.
    /// </summary>
    public const string PostgresVariable = "AEGIS_BENCH_POSTGRES";

    public static string? PostgresConnectionString =>
        Environment.GetEnvironmentVariable(PostgresVariable) is { Length: > 0 } value ? value : null;

    /// <summary>
    /// Source for <c>[ParamsSource]</c>: SQLite always, PostgreSQL when a server is configured.
    /// </summary>
    public static IEnumerable<DatabaseProvider> AvailableProviders()
    {
        yield return DatabaseProvider.Sqlite;

        if (PostgresConnectionString is not null)
        {
            yield return DatabaseProvider.Postgres;
        }
    }
}
