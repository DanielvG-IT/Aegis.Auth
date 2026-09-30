using Aegis.Auth.Abstractions;
using Aegis.Auth.Core.Crypto;
using Aegis.Auth.Entities;
using Aegis.Auth.Infrastructure.Auth;
using Aegis.Auth.Infrastructure.Cookies;
using Aegis.Auth.Options;
using Aegis.Auth.Tests.Helpers;

using Microsoft.AspNetCore.Http;

namespace Aegis.Auth.Tests.Features;

public sealed class AuthContextAccessorTests : IDisposable
{
    private readonly ServiceTestFixture _fixture;
    private readonly SessionCookieHandler _cookieHandler;
    private readonly IAegisAuthContextAccessor _sut;

    public AuthContextAccessorTests()
    {
        _fixture = new ServiceTestFixture();
        _cookieHandler = new SessionCookieHandler(_fixture.Options, isDevelopment: true, _fixture.Time);
        _sut = new AegisAuthContextAccessor(_cookieHandler, _fixture.DbContext, _fixture.Time);
    }

    public void Dispose() => _fixture.Dispose();

    [Fact]
    public async Task GetCurrentAsync_ValidSignedCookieAndSession_ReturnsAuthContext()
    {
        (User user, _) = await _fixture.SeedUserAsync();
        Session session = await SeedSessionAsync(user, token: "valid-token");

        DefaultHttpContext httpContext = CreateHttpContextWithSessionCookie("valid-token");

        AegisAuthContext? context = await _sut.GetCurrentAsync(httpContext);

        Assert.NotNull(context);
        Assert.Equal(user.Id, context!.UserId);
        Assert.Equal(session.Token, context.SessionToken);
        Assert.False(context.IsFromCookieCache);
    }

    [Fact]
    public async Task GetCurrentAsync_MissingCookie_ReturnsNull()
    {
        var httpContext = new DefaultHttpContext();

        AegisAuthContext? context = await _sut.GetCurrentAsync(httpContext);

        Assert.Null(context);
    }

    [Fact]
    public async Task GetCurrentAsync_TamperedCookieSignature_ReturnsNull()
    {
        (User user, _) = await _fixture.SeedUserAsync();
        await SeedSessionAsync(user, token: "valid-token");

        var httpContext = new DefaultHttpContext();
        httpContext.Request.Headers.Cookie = "aegis.session=valid-token.invalid-signature";

        AegisAuthContext? context = await _sut.GetCurrentAsync(httpContext);

        Assert.Null(context);
    }

    [Fact]
    public async Task GetCurrentAsync_ExpiredSession_ReturnsNull()
    {
        (User user, _) = await _fixture.SeedUserAsync();
        Session session = await SeedSessionAsync(user, token: "expired-token");
        _fixture.Time.Advance(session.ExpiresAt - _fixture.Time.GetUtcNow().UtcDateTime);

        DefaultHttpContext httpContext = CreateHttpContextWithSessionCookie("expired-token");

        AegisAuthContext? context = await _sut.GetCurrentAsync(httpContext);

        Assert.Null(context);
    }

    [Fact]
    public async Task GetCurrentAsync_ValidCookieCache_ReturnsAuthContextFromCookieCache()
    {
        using var fixture = new ServiceTestFixture(options =>
        {
            options.Session.CookieCache = new CookieCacheOptions
            {
                Enabled = true,
                MaxAge = 300,
            };
        });

        var cookieHandler = new SessionCookieHandler(fixture.Options, isDevelopment: true, fixture.Time);
        IAegisAuthContextAccessor sut = new AegisAuthContextAccessor(cookieHandler, fixture.DbContext, fixture.Time);

        (User user, _) = await fixture.SeedUserAsync();
        Session session = await SeedSessionAsync(fixture, user, token: "cached-token");

        DefaultHttpContext httpContext = CreateHttpContextWithSessionCookies(cookieHandler, session, user);

        AegisAuthContext? context = await sut.GetCurrentAsync(httpContext);

        Assert.NotNull(context);
        Assert.Equal(user.Id, context!.UserId);
        Assert.Equal(session.Token, context.SessionToken);
        Assert.Equal(session.ExpiresAt, context.ExpiresAt);
        Assert.True(context.IsFromCookieCache);
    }

    [Fact]
    public async Task GetCurrentAsync_CookieCacheExpired_FallsBackToDatabase()
    {
        using var fixture = new ServiceTestFixture(options =>
        {
            options.Session.CookieCache = new CookieCacheOptions
            {
                Enabled = true,
                MaxAge = 300,
            };
        });

        var cookieHandler = new SessionCookieHandler(fixture.Options, isDevelopment: true, fixture.Time);
        IAegisAuthContextAccessor sut = new AegisAuthContextAccessor(cookieHandler, fixture.DbContext, fixture.Time);

        (User user, _) = await fixture.SeedUserAsync();
        Session session = await SeedSessionAsync(fixture, user, token: "cached-token");
        DefaultHttpContext httpContext = CreateHttpContextWithSessionCookies(cookieHandler, session, user);

        fixture.Time.Advance(TimeSpan.FromSeconds(301));
        AegisAuthContext? context = await sut.GetCurrentAsync(httpContext);

        Assert.NotNull(context);
        Assert.Equal(user.Id, context!.UserId);
        Assert.False(context.IsFromCookieCache);
    }

    private DefaultHttpContext CreateHttpContextWithSessionCookie(string token)
    {
        var signedToken = AegisSigner.Sign(token, _fixture.Options.Secret);

        var httpContext = new DefaultHttpContext();
        httpContext.Request.Headers.Cookie = $"aegis.session={signedToken}";
        return httpContext;
    }

    private static DefaultHttpContext CreateHttpContextWithSessionCookies(SessionCookieHandler cookieHandler, Session session, User user)
    {
        var responseContext = new DefaultHttpContext();
        cookieHandler.SetSessionCookie(responseContext, session, user, rememberMe: true);

        var requestCookies = responseContext.Response.Headers.SetCookie
            .Select(static cookie => (cookie ?? string.Empty).Split(';', 2)[0])
            .Where(static cookie => string.IsNullOrWhiteSpace(cookie) is false)
            .ToArray();

        var cookieHeader = string.Join("; ", requestCookies);

        var requestContext = new DefaultHttpContext();
        requestContext.Request.Headers.Cookie = cookieHeader;
        return requestContext;
    }

    private Task<Session> SeedSessionAsync(User user, string token, DateTime? expiresAt = null)
        => SeedSessionAsync(_fixture, user, token, expiresAt);

    private static async Task<Session> SeedSessionAsync(ServiceTestFixture fixture, User user, string token, DateTime? expiresAt = null)
    {
        DateTime now = fixture.Time.GetUtcNow().UtcDateTime;
        var session = new Session
        {
            Id = Guid.CreateVersion7().ToString(),
            Token = token,                            // [NotMapped] – kept for assertion convenience
            TokenHash = AegisCrypto.HashToken(token), // the only value persisted to the DB
            ExpiresAt = expiresAt ?? now.AddDays(7),
            UserId = user.Id,
            User = user,
            IpAddress = "127.0.0.1",
            UserAgent = "TestAgent/1.0",
            CreatedAt = now,
            UpdatedAt = now,
        };

        fixture.DbContext.Sessions.Add(session);
        await fixture.DbContext.SaveChangesAsync();
        return session;
    }
}
