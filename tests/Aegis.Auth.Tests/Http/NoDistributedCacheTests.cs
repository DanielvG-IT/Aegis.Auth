using System.Net;
using System.Net.Http.Json;

using Aegis.Auth.Extensions;
using Aegis.Auth.Http.Extensions;
using Aegis.Auth.Options;
using Aegis.Auth.Tests.Helpers;

using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

namespace Aegis.Auth.Tests.Http;

/// <summary>
/// The distributed cache is optional: a host without any <see cref="IDistributedCache"/> registration
/// must still build (with DI validation on) and keep sessions in the database only.
/// </summary>
public sealed class NoDistributedCacheTests
{
    private const string Email = "no-cache@test.com";
    private const string Password = "NoCachePass123!";

    [Fact]
    public async Task SignIn_WithoutDistributedCache_CreatesDatabaseSession()
    {
        var dbName = $"AegisNoCacheTest_{Guid.NewGuid():N}";

        // A generic host rather than WebApplication: WebApplication auto-adds the authentication middleware,
        // which sign-up/sign-in don't need, so this keeps the test independent of OAuth scheme configuration.
        using IHost host = await new HostBuilder()
            .UseEnvironment(Environments.Development)
            // ValidateOnBuild is what surfaces a constructor dependency the container cannot resolve.
            .UseDefaultServiceProvider(o =>
            {
                o.ValidateOnBuild = true;
                o.ValidateScopes = true;
            })
            .ConfigureWebHost(web => web
                .UseTestServer()
                .ConfigureServices(services =>
                {
                    services.AddRouting();
                    services.AddDbContext<TestDbContext>(o => o.UseInMemoryDatabase(dbName));
                    // Deliberately no AddDistributedMemoryCache().
                    services.AddAegisAuth<TestDbContext>(options =>
                    {
                        options.AppName = "AegisNoCacheTest";
                        options.BaseURL = "http://localhost";
                        options.Secret = "test-secret-that-is-long-enough-for-hmac-256-operations!!";
                        options.EmailAndPassword.Password = new PasswordOptions
                        {
                            Hash = password => Task.FromResult($"hashed:{password}"),
                            Verify = ctx => Task.FromResult(ctx.Hash == $"hashed:{ctx.Password}"),
                        };
                    });
                })
                .Configure(app => app
                    .UseRouting()
                    .UseEndpoints(endpoints => endpoints.MapAegisAuthEndpoints())))
            .StartAsync();
        using HttpClient client = host.GetTestClient();

        Assert.Null(host.Services.GetService<IDistributedCache>());

        HttpResponseMessage signUp = await client.PostAsJsonAsync("/api/auth/sign-up/email", new { name = "No Cache", email = Email, password = Password });
        Assert.True(signUp.IsSuccessStatusCode, await signUp.Content.ReadAsStringAsync());
        var sessionsAfterSignUp = await CountSessionsAsync(host.Services);

        HttpResponseMessage signIn = await client.PostAsJsonAsync("/api/auth/sign-in/email", new { email = Email, password = Password });

        Assert.Equal(HttpStatusCode.OK, signIn.StatusCode);
        Assert.Contains(signIn.Headers.GetValues("Set-Cookie"), c => c.StartsWith("aegis.session=", StringComparison.Ordinal));
        Assert.Equal(sessionsAfterSignUp + 1, await CountSessionsAsync(host.Services));
    }

    private static async Task<int> CountSessionsAsync(IServiceProvider services)
    {
        using IServiceScope scope = services.CreateScope();
        return await scope.ServiceProvider.GetRequiredService<TestDbContext>().Sessions.CountAsync();
    }
}
