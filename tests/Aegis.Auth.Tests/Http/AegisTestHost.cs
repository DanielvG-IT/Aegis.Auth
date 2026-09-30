using System.Net;

using Aegis.Auth.Abstractions;
using Aegis.Auth.Extensions;
using Aegis.Auth.Http.Extensions;
using Aegis.Auth.Options;
using Aegis.Auth.Plugins;
using Aegis.Auth.Tests.Helpers;

using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Time.Testing;

namespace Aegis.Auth.Tests.Http;

/// <summary>
/// Spins up the real Aegis HTTP pipeline on an in-memory TestServer.
/// </summary>
internal sealed class AegisTestHost : IAsyncDisposable
{
    /// <summary>
    /// TestServer connections have no remote address; requests carrying this header get it as
    /// <c>Connection.RemoteIpAddress</c>, standing in for the forwarded headers middleware.
    /// </summary>
    public const string ClientIpHeader = "X-Test-Client-IP";

    private readonly WebApplication _app;
    private readonly SqliteConnection? _keepAlive;

    public HttpClient Client { get; }
    public IServiceProvider Services => _app.Services;
    public TestServer Server => _app.GetTestServer();

    private AegisTestHost(WebApplication app, SqliteConnection? keepAlive)
    {
        _app = app;
        _keepAlive = keepAlive;
        Client = app.GetTestClient();
    }

    public static async Task<AegisTestHost> StartAsync(
        Action<AegisAuthOptions>? configure = null,
        Action<AegisAuthEndpointMapOptions>? configureEndpoints = null,
        Action<IServiceCollection>? configureServices = null,
        FakeTimeProvider? timeProvider = null,
        Action<IAegisAuthBuilder>? configureAegis = null)
    {
        // Shared-cache SQLite in-memory: a real relational database (ExecuteUpdate, transactions) that lives
        // while the keep-alive connection is open, with a connection per request scope like production.
        var connectionString = $"Data Source=AegisHttpTest_{Guid.NewGuid():N};Mode=Memory;Cache=Shared";
        var keepAlive = new SqliteConnection(connectionString);
        keepAlive.Open();
        try
        {
            return await StartCoreAsync<TestDbContext>(
                db => db.UseSqlite(connectionString), keepAlive, configure, configureEndpoints, configureServices,
                configureApp: null, baseAddress: null, timeProvider, configureAegis);
        }
        catch
        {
            await keepAlive.DisposeAsync();
            throw;
        }
    }

    /// <summary>
    /// Same pipeline over a caller-supplied <typeparamref name="TContext"/>, for tests that need a
    /// relational provider or extra entities. <paramref name="configureApp"/> maps additional
    /// endpoints after the Aegis ones; <paramref name="baseAddress"/> sets the scheme and host
    /// the server sees (and <see cref="AegisAuthOptions.BaseURL"/>).
    /// </summary>
    public static Task<AegisTestHost> StartAsync<TContext>(
        Action<DbContextOptionsBuilder> configureDbContext,
        Action<AegisAuthOptions>? configure = null,
        Action<AegisAuthEndpointMapOptions>? configureEndpoints = null,
        Action<IServiceCollection>? configureServices = null,
        Action<WebApplication>? configureApp = null,
        Uri? baseAddress = null)
        where TContext : DbContext, IAuthDbContext =>
        StartCoreAsync<TContext>(
            configureDbContext, keepAlive: null, configure, configureEndpoints, configureServices,
            configureApp, baseAddress, timeProvider: null, configureAegis: null);

    private static async Task<AegisTestHost> StartCoreAsync<TContext>(
        Action<DbContextOptionsBuilder> configureDbContext,
        SqliteConnection? keepAlive,
        Action<AegisAuthOptions>? configure,
        Action<AegisAuthEndpointMapOptions>? configureEndpoints,
        Action<IServiceCollection>? configureServices,
        Action<WebApplication>? configureApp,
        Uri? baseAddress,
        FakeTimeProvider? timeProvider,
        Action<IAegisAuthBuilder>? configureAegis)
        where TContext : DbContext, IAuthDbContext
    {
        WebApplicationBuilder builder = WebApplication.CreateBuilder(new WebApplicationOptions
        {
            EnvironmentName = Environments.Development,
        });
        builder.WebHost.UseTestServer(o =>
        {
            if (baseAddress is not null)
            {
                o.BaseAddress = baseAddress;
            }
        });

        builder.Services.AddDbContext<TContext>((sp, o) =>
        {
            configureDbContext(o);
            o.UseAegisAuth(sp);
        });
        builder.Services.AddDistributedMemoryCache();
        if (timeProvider is not null)
        {
            // Registered before AddAegisAuth so its TryAddSingleton(TimeProvider.System) is skipped.
            builder.Services.AddSingleton<TimeProvider>(timeProvider);
        }

        IAegisAuthBuilder aegis = builder.Services.AddAegisAuth<TContext>(options =>
        {
            options.AppName = "AegisHttpTest";
            options.BaseURL = baseAddress?.GetLeftPart(UriPartial.Authority) ?? "http://localhost";
            options.Secret = "test-secret-that-is-long-enough-for-hmac-256-operations!!";
            options.EmailAndPassword.Enabled = true;
            options.EmailAndPassword.Password = new PasswordOptions
            {
                Hash = password => Task.FromResult($"hashed:{password}"),
                Verify = ctx => Task.FromResult(ctx.Hash == $"hashed:{ctx.Password}"),
            };
            configure?.Invoke(options);
        });
        configureAegis?.Invoke(aegis);

        configureServices?.Invoke(builder.Services);

        WebApplication app = builder.Build();
        using (IServiceScope scope = app.Services.CreateScope())
        {
            scope.ServiceProvider.GetRequiredService<TContext>().Database.EnsureCreated();
        }

        app.Use((context, next) =>
        {
            if (context.Request.Headers.TryGetValue(ClientIpHeader, out var clientIp))
            {
                context.Connection.RemoteIpAddress = IPAddress.Parse(clientIp.ToString());
            }

            return next(context);
        });
        app.UseAuthentication();
        app.UseAuthorization();
        app.MapAegisAuthEndpoints(configureEndpoints);
        configureApp?.Invoke(app);

        await app.StartAsync();
        return new AegisTestHost(app, keepAlive);
    }

    public async ValueTask DisposeAsync()
    {
        Client.Dispose();
        await _app.StopAsync();
        await _app.DisposeAsync();
        if (_keepAlive is not null)
        {
            await _keepAlive.DisposeAsync();
        }
    }
}
