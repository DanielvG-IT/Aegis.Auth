using Aegis.Auth.Benchmarks.Infrastructure;

using BenchmarkDotNet.Running;

using Testcontainers.PostgreSql;

// Usage: dotnet run -c Release --project benchmarks/Aegis.Auth.Benchmarks -- [--postgres] [BenchmarkDotNet args]
//   --postgres   start PostgreSQL in Docker (Testcontainers) and add it to the database benchmarks.
//                Alternatively set AEGIS_BENCH_POSTGRES to the connection string of an existing server.
// Everything else goes to BenchmarkDotNet, e.g. --filter '*Query*' or --list flat.

var usePostgresContainer = args.Contains("--postgres", StringComparer.OrdinalIgnoreCase);
var benchmarkArgs = args.Where(a => !string.Equals(a, "--postgres", StringComparison.OrdinalIgnoreCase)).ToArray();

PostgreSqlContainer? postgres = null;
if (usePostgresContainer && BenchEnvironment.PostgresConnectionString is null)
{
    Console.WriteLine("Starting PostgreSQL (Testcontainers)...");
    postgres = new PostgreSqlBuilder("postgres:17-alpine").Build();
    await postgres.StartAsync();
    Environment.SetEnvironmentVariable(BenchEnvironment.PostgresVariable, postgres.GetConnectionString());
}

try
{
    BenchmarkSwitcher.FromAssembly(typeof(BenchConfig).Assembly).Run(benchmarkArgs, BenchConfig.Create());
}
finally
{
    if (postgres is not null)
    {
        await postgres.DisposeAsync();
    }
}
