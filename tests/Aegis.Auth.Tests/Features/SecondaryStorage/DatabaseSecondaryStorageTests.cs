using Aegis.Auth.Abstractions;
using Aegis.Auth.Entities;
using Aegis.Auth.Features.SecondaryStorage;
using Aegis.Auth.Tests.Helpers;

using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;

namespace Aegis.Auth.Tests.Features.SecondaryStorage;

/// <summary>
/// Runs against SQLite (shared-cache in-memory database, one connection per DbContext) because the
/// implementation depends on primary-key conflicts and ExecuteUpdate, which EF InMemory does not support.
/// </summary>
public sealed class DatabaseSecondaryStorageTests : SecondaryStorageContractTests, IDisposable
{
    private readonly SqliteConnection _keepAlive;
    private readonly ServiceProvider _services;

    public DatabaseSecondaryStorageTests()
    {
        var connectionString = $"Data Source=file:aegis-kv-{Guid.NewGuid():N}?mode=memory&cache=shared";
        // The in-memory database lives as long as one connection to it is open.
        _keepAlive = new SqliteConnection(connectionString);
        _keepAlive.Open();

        var services = new ServiceCollection();
        services.AddDbContext<SqliteAuthDbContext>(o => o.UseSqlite(connectionString));
        services.AddScoped<IAuthDbContext>(sp => sp.GetRequiredService<SqliteAuthDbContext>());
        _services = services.BuildServiceProvider(new ServiceProviderOptions { ValidateScopes = true });

        using IServiceScope scope = _services.CreateScope();
        scope.ServiceProvider.GetRequiredService<SqliteAuthDbContext>().Database.EnsureCreated();
    }

    protected override IAegisSecondaryStorage CreateStorage(TimeProvider timeProvider) =>
        new DatabaseSecondaryStorage(_services.GetRequiredService<IServiceScopeFactory>(), timeProvider, NullLoggerFactory.Instance);

    public void Dispose()
    {
        _services.Dispose();
        _keepAlive.Dispose();
    }

    [Fact]
    public async Task Write_AfterSweepInterval_PurgesExpiredRows()
    {
        await Storage.SetAsync("expired", "v", TimeSpan.FromSeconds(1));
        await Storage.SetAsync("alive", "v", TimeSpan.FromHours(1));

        Clock.Advance(DatabaseSecondaryStorage.SweepInterval);
        await Storage.SetAsync("trigger", "v", TimeSpan.FromHours(1));

        Assert.Equal(["alive", "trigger"], await ReadKeysAsync());
    }

    [Fact]
    public async Task SetIfNotExists_OverExpiredRow_ReplacesIt()
    {
        await Storage.SetAsync("key", "old", TimeSpan.FromSeconds(1));
        Clock.Advance(TimeSpan.FromSeconds(2));

        Assert.True(await Storage.SetIfNotExistsAsync("key", "new", TimeSpan.FromMinutes(1)));

        using IServiceScope scope = _services.CreateScope();
        AegisKeyValue row = await scope.ServiceProvider.GetRequiredService<SqliteAuthDbContext>().AegisKeyValues.SingleAsync();
        Assert.Equal("new", row.Value);
    }

    [Fact]
    public async Task Operations_DoNotFlushCallersPendingChanges()
    {
        using IServiceScope scope = _services.CreateScope();
        SqliteAuthDbContext callerDb = scope.ServiceProvider.GetRequiredService<SqliteAuthDbContext>();
        callerDb.AegisKeyValues.Add(new AegisKeyValue { Key = "pending", Value = "v", ExpiresAt = DateTime.UtcNow.AddHours(1) });

        await Storage.SetAsync("key", "v", TimeSpan.FromMinutes(1));

        Assert.Equal(["key"], await ReadKeysAsync());
    }

    private async Task<List<string>> ReadKeysAsync()
    {
        using IServiceScope scope = _services.CreateScope();
        return await scope.ServiceProvider.GetRequiredService<SqliteAuthDbContext>().AegisKeyValues
            .Select(e => e.Key)
            .OrderBy(k => k)
            .ToListAsync();
    }
}
