using Aegis.Auth.Extensions;
using Aegis.Auth.Http.Extensions;
using Aegis.Auth.Options;
using Aegis.Auth.Tests.Helpers;

using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

namespace Aegis.Auth.Tests.Http;

/// <summary>
/// Spins up the real Aegis HTTP pipeline on an in-memory TestServer.
/// </summary>
internal sealed class AegisTestHost : IAsyncDisposable
{
    private readonly WebApplication _app;

    public HttpClient Client { get; }
    public IServiceProvider Services => _app.Services;

    private AegisTestHost(WebApplication app)
    {
        _app = app;
        Client = app.GetTestClient();
    }

    public static async Task<AegisTestHost> StartAsync(
        Action<AegisAuthOptions>? configure = null,
        Action<AegisAuthEndpointMapOptions>? configureEndpoints = null)
    {
        WebApplicationBuilder builder = WebApplication.CreateBuilder(new WebApplicationOptions
        {
            EnvironmentName = Environments.Development,
        });
        builder.WebHost.UseTestServer();

        var dbName = $"AegisHttpTest_{Guid.NewGuid():N}";
        builder.Services.AddDbContext<TestDbContext>(o => o.UseInMemoryDatabase(dbName));
        builder.Services.AddDistributedMemoryCache();
        builder.Services.AddAegisAuth<TestDbContext>(options =>
        {
            options.AppName = "AegisHttpTest";
            options.BaseURL = "http://localhost";
            options.Secret = "test-secret-that-is-long-enough-for-hmac-256-operations!!";
            options.EmailAndPassword.Password = new PasswordOptions
            {
                Hash = password => Task.FromResult($"hashed:{password}"),
                Verify = ctx => Task.FromResult(ctx.Hash == $"hashed:{ctx.Password}"),
            };
            configure?.Invoke(options);
        });

        WebApplication app = builder.Build();
        app.UseAuthentication();
        app.UseAuthorization();
        app.MapAegisAuthEndpoints(configureEndpoints);

        await app.StartAsync();
        return new AegisTestHost(app);
    }

    public async ValueTask DisposeAsync()
    {
        Client.Dispose();
        await _app.StopAsync();
        await _app.DisposeAsync();
    }
}
