using System.Collections.Concurrent;

using Aegis.Auth.Extensions;
using Aegis.Auth.Features.SecondaryStorage;
using Aegis.Auth.Tests.Helpers;

using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace Aegis.Auth.Tests.Features.SecondaryStorage;

public sealed class SecondaryStorageRegistrationTests
{
    private const int NotAtomicEventId = 9000;

    [Fact]
    public void AddAegisAuth_RegistersInMemoryStorageAsSingleton()
    {
        using ServiceProvider sp = Build(_ => { });

        IAegisSecondaryStorage storage = sp.GetRequiredService<IAegisSecondaryStorage>();
        Assert.IsType<InMemorySecondaryStorage>(storage);
        Assert.Same(storage, sp.GetRequiredService<IAegisSecondaryStorage>());
        Assert.Same(TimeProvider.System, sp.GetRequiredService<TimeProvider>());
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void AddAegisDatabaseSecondaryStorage_ReplacesDefault_RegardlessOfOrder(bool beforeAddAegisAuth)
    {
        using ServiceProvider sp = Build(s => s.AddAegisDatabaseSecondaryStorage(), beforeAddAegisAuth);

        Assert.IsType<DatabaseSecondaryStorage>(sp.GetRequiredService<IAegisSecondaryStorage>());
        Assert.Single(sp.GetServices<IAegisSecondaryStorage>());
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void AddAegisDistributedCacheSecondaryStorage_ReplacesDefault_RegardlessOfOrder(bool beforeAddAegisAuth)
    {
        using ServiceProvider sp = Build(
            s => s.AddDistributedMemoryCache().AddAegisDistributedCacheSecondaryStorage(),
            beforeAddAegisAuth);

        Assert.IsType<DistributedCacheSecondaryStorage>(sp.GetRequiredService<IAegisSecondaryStorage>());
    }

    [Fact]
    public void CustomStorage_RegisteredBeforeAddAegisAuth_IsKept()
    {
        using ServiceProvider sp = Build(s => s.AddSingleton<IAegisSecondaryStorage, CustomStorage>(), beforeAddAegisAuth: true);

        Assert.IsType<CustomStorage>(sp.GetRequiredService<IAegisSecondaryStorage>());
    }

    [Fact]
    public async Task Startup_WithDistributedCacheStorage_LogsNonAtomicWarning()
    {
        var logs = new ListLoggerProvider();
        using ServiceProvider sp = Build(s => s.AddDistributedMemoryCache().AddAegisDistributedCacheSecondaryStorage(), logs: logs);

        await StartDiagnosticsAsync(sp);

        LogEntry entry = Assert.Single(logs.Entries, e => e.EventId == NotAtomicEventId);
        Assert.Equal(LogLevel.Warning, entry.Level);
        Assert.Contains("not atomic", entry.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Startup_WithDefaultStorage_DoesNotWarn()
    {
        var logs = new ListLoggerProvider();
        using ServiceProvider sp = Build(_ => { }, logs: logs);

        await StartDiagnosticsAsync(sp);

        Assert.DoesNotContain(logs.Entries, e => e.EventId == NotAtomicEventId);
    }

    [Fact]
    public async Task Startup_DistributedCacheStorageWithoutCache_FailsWithClearMessage()
    {
        using ServiceProvider sp = Build(s => s.AddAegisDistributedCacheSecondaryStorage());

        InvalidOperationException ex = await Assert.ThrowsAsync<InvalidOperationException>(() => StartDiagnosticsAsync(sp));
        Assert.Contains("requires an IDistributedCache", ex.Message, StringComparison.Ordinal);
    }

    private static ServiceProvider Build(Action<IServiceCollection> configure, bool beforeAddAegisAuth = false, ListLoggerProvider? logs = null)
    {
        var services = new ServiceCollection();
        services.AddLogging(b =>
        {
            if (logs is not null)
            {
                b.AddProvider(logs);
            }
        });
        services.AddDbContext<TestDbContext>(o => o.UseInMemoryDatabase($"SecondaryStorageRegistration_{Guid.NewGuid():N}"));

        if (beforeAddAegisAuth)
        {
            configure(services);
        }

        services.AddAegisAuth<TestDbContext>(o =>
        {
            o.AppName = "SecondaryStorageTest";
            o.BaseURL = "http://localhost";
            o.Secret = "test-secret-that-is-long-enough-for-hmac-256-operations!!";
        });

        if (beforeAddAegisAuth is false)
        {
            configure(services);
        }

        return services.BuildServiceProvider(new ServiceProviderOptions { ValidateScopes = true });
    }

    private static Task StartDiagnosticsAsync(IServiceProvider sp) =>
        sp.GetServices<IHostedService>().OfType<SecondaryStorageStartupDiagnostics>().Single().StartAsync(CancellationToken.None);

    private sealed class CustomStorage : IAegisSecondaryStorage
    {
        public Task<string?> GetAsync(string key, CancellationToken ct = default) => throw new NotSupportedException();
        public Task SetAsync(string key, string value, TimeSpan ttl, CancellationToken ct = default) => throw new NotSupportedException();
        public Task<bool> DeleteAsync(string key, CancellationToken ct = default) => throw new NotSupportedException();
        public Task<long> IncrementAsync(string key, TimeSpan ttl, CancellationToken ct = default) => throw new NotSupportedException();
        public Task<bool> SetIfNotExistsAsync(string key, string value, TimeSpan ttl, CancellationToken ct = default) => throw new NotSupportedException();
    }

    private sealed record LogEntry(int EventId, LogLevel Level, string Message);

    private sealed class ListLoggerProvider : ILoggerProvider
    {
        private readonly ConcurrentQueue<LogEntry> _entries = new();

        public IReadOnlyCollection<LogEntry> Entries => _entries;

        public ILogger CreateLogger(string categoryName) => new ListLogger(_entries);

        public void Dispose() { }

        private sealed class ListLogger(ConcurrentQueue<LogEntry> entries) : ILogger
        {
            public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;

            public bool IsEnabled(LogLevel logLevel) => true;

            public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter) =>
                entries.Enqueue(new LogEntry(eventId.Id, logLevel, formatter(state, exception)));
        }
    }
}
