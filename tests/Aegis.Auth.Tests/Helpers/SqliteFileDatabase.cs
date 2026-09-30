using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;

namespace Aegis.Auth.Tests.Helpers;

/// <summary>
/// A temporary SQLite database file for concurrency tests. Unlike an in-memory database, every
/// <see cref="CreateContext"/> gets its own connection, so parallel requests really race in the database.
/// </summary>
internal sealed class SqliteFileDatabase : IDisposable
{
    private readonly string _path = Path.Combine(Path.GetTempPath(), $"aegis-test-{Guid.NewGuid():N}.db");
    private readonly string _connectionString;

    public SqliteFileDatabase()
    {
        _connectionString = new SqliteConnectionStringBuilder
        {
            DataSource = _path,
            Pooling = false,
            DefaultTimeout = 30,
        }.ToString();

        using TestDbContext context = CreateContext();
        context.Database.EnsureCreated();
    }

    public TestDbContext CreateContext() =>
        new(new DbContextOptionsBuilder<TestDbContext>().UseSqlite(_connectionString).Options);

    public void Dispose() => File.Delete(_path);
}
