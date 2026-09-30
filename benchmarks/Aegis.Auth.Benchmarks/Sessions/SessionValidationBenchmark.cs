using System.Security.Claims;

using Aegis.Auth.Abstractions;
using Aegis.Auth.Benchmarks.Infrastructure;
using Aegis.Auth.Entities;
using Aegis.Auth.Extensions;
using Aegis.Auth.Features.Sessions;
using Aegis.Auth.Infrastructure.Cookies;
using Aegis.Auth.Options;

using BenchmarkDotNet.Attributes;

using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace Aegis.Auth.Benchmarks.Sessions;

/// <summary>
/// One authenticated request through the real <c>AegisAuthenticationHandler</c>: DI scope, cookie parsing, HMAC
/// verification, then the session source under test. The cookie-cache rows do not touch the database, so they
/// should read the same for every provider.
/// </summary>
[BenchmarkCategory("Session")]
public class SessionValidationBenchmark
{
    private BenchDatabase _database = null!;
    private ServiceProvider _compact = null!;
    private ServiceProvider _encrypted = null!;
    private ServiceProvider _secondaryStorage = null!;

    private string _compactCookies = string.Empty;
    private string _encryptedCookies = string.Empty;
    private string _sessionCookieOnly = string.Empty;
    private string _userId = string.Empty;

    [ParamsSource(typeof(BenchEnvironment), nameof(BenchEnvironment.AvailableProviders))]
    public DatabaseProvider Provider { get; set; }

    [GlobalSetup]
    public async Task Setup()
    {
        _database = await BenchDatabase.CreateAsync(Provider);
        _compact = AegisServices.Build(_database, o => o.Session.CookieCache = new CookieCacheOptions { Mode = CookieCacheMode.Compact });
        _encrypted = AegisServices.Build(_database, o => o.Session.CookieCache = new CookieCacheOptions { Mode = CookieCacheMode.Encrypted });
        _secondaryStorage = AegisServices.Build(_database, configureServices: services =>
        {
            services.AddDistributedMemoryCache();
            services.Replace(ServiceDescriptor.Scoped<IAegisAuthContextAccessor, SecondaryStorageContextAccessor>());
        });

        // A real session, created by SessionService: a database row plus the distributed-cache entry.
        Session session;
        User user;
        await using (AsyncServiceScope scope = _secondaryStorage.CreateAsyncScope())
        {
            user = await scope.ServiceProvider.GetRequiredService<BenchDbContext>().Users
                .AsNoTracking()
                .FirstAsync(u => u.Id == BenchDatabase.UserId(BenchDatabase.TargetIndex));
            Result<Session> created = await scope.ServiceProvider.GetRequiredService<ISessionService>().CreateSessionAsync(new SessionCreateInput
            {
                User = user,
                IpAddress = "203.0.113.10",
                UserAgent = "Aegis.Auth.Benchmarks",
            });
            session = created.Value ?? throw new InvalidOperationException("Could not create the benchmark session.");
        }

        _userId = user.Id;
        _compactCookies = IssueCookies(_compact, session, user);
        _encryptedCookies = IssueCookies(_encrypted, session, user);
        _sessionCookieOnly = IssueCookies(_compact, session, user, name => !name.Contains("session_data", StringComparison.Ordinal));

        await Expect(CookieCacheHitCompact, fromCookieCache: true);
        await Expect(CookieCacheHitEncrypted, fromCookieCache: true);
        await Expect(DatabaseLookup, fromCookieCache: false);
        await Expect(SecondaryStorage, fromCookieCache: false);
    }

    [GlobalCleanup]
    public async Task Cleanup()
    {
        await _compact.DisposeAsync();
        await _encrypted.DisposeAsync();
        await _secondaryStorage.DisposeAsync();
        await _database.DisposeAsync();
    }

    [Benchmark]
    public Task<HttpContext> CookieCacheHitCompact() => AuthenticateAsync(_compact, _compactCookies);

    [Benchmark]
    public Task<HttpContext> CookieCacheHitEncrypted() => AuthenticateAsync(_encrypted, _encryptedCookies);

    [Benchmark(Baseline = true)]
    public Task<HttpContext> DatabaseLookup() => AuthenticateAsync(_compact, _sessionCookieOnly);

    [Benchmark]
    public Task<HttpContext> SecondaryStorage() => AuthenticateAsync(_secondaryStorage, _sessionCookieOnly);

    private static async Task<HttpContext> AuthenticateAsync(IServiceProvider services, string cookieHeader)
    {
        await using AsyncServiceScope scope = services.CreateAsyncScope();
        var context = new DefaultHttpContext { RequestServices = scope.ServiceProvider };
        context.Request.Headers.Cookie = cookieHeader;

        AuthenticateResult result = await context.AuthenticateAsync();
        context.User = result.Principal ?? context.User;
        return context;
    }

    private static string IssueCookies(IServiceProvider services, Session session, User user, Func<string, bool>? include = null)
    {
        using IServiceScope scope = services.CreateScope();
        var context = new DefaultHttpContext { RequestServices = scope.ServiceProvider };
        scope.ServiceProvider.GetRequiredService<SessionCookieHandler>().SetSessionCookie(context, session, user, rememberMe: true);
        return AegisServices.ToRequestCookieHeader(context.Response, include);
    }

    private async Task Expect(Func<Task<HttpContext>> variant, bool fromCookieCache)
    {
        HttpContext context = await variant();
        AegisAuthContext? auth = context.GetAegisAuthContext();
        if (context.User.FindFirstValue(ClaimTypes.NameIdentifier) != _userId || auth is null || auth.IsFromCookieCache != fromCookieCache)
        {
            throw new InvalidOperationException($"{nameof(SessionValidationBenchmark)}: {variant.Method.Name} did not authenticate through the expected path.");
        }
    }
}
