using Aegis.Auth.Constants;
using Aegis.Auth.Entities;
using Aegis.Auth.Features.Sessions;
using Aegis.Auth.Features.SignOut;
using Aegis.Auth.Tests.Helpers;

using Microsoft.EntityFrameworkCore;

using Moq;

namespace Aegis.Auth.Tests.Features;

/// <summary>
/// Adversarial test suite for SignOutService.
/// Focus: token manipulation, session tampering, revocation guarantees.
/// </summary>
public sealed class SignOutServiceTests : IDisposable
{
    private readonly ServiceTestFixture _fixture;
    private readonly Mock<ISessionService> _sessionMock;
    private readonly SignOutService _sut;

    public SignOutServiceTests()
    {
        _fixture = new ServiceTestFixture();
        _sessionMock = new Mock<ISessionService>(MockBehavior.Strict);
        _sut = new SignOutService(
            _fixture.LoggerFactory,
            _fixture.DbContext,
            _sessionMock.Object);
    }

    public void Dispose() => _fixture.Dispose();

    // ═══════════════════════════════════════════════════════════════════════════
    // SESSION NOT FOUND — Token that doesn't exist
    // ═══════════════════════════════════════════════════════════════════════════

    [Fact]
    public async Task SignOut_NonExistentToken_ReturnsSessionNotFound()
    {
        var input = new SignOutInput { Token = "non-existent-token" };

        Result result = await _sut.SignOut(input);

        Assert.False(result.IsSuccess);
        Assert.Equal(AuthErrors.Session.SessionNotFound, result.ErrorCode);
    }

    [Fact]
    public async Task SignOut_EmptyToken_ReturnsSessionNotFound()
    {
        var input = new SignOutInput { Token = string.Empty };

        Result result = await _sut.SignOut(input);

        Assert.False(result.IsSuccess);
        Assert.Equal(AuthErrors.Session.SessionNotFound, result.ErrorCode);
    }

    [Fact]
    public async Task SignOut_WhitespaceToken_ReturnsSessionNotFound()
    {
        var input = new SignOutInput { Token = "   " };

        Result result = await _sut.SignOut(input);

        Assert.False(result.IsSuccess);
        Assert.Equal(AuthErrors.Session.SessionNotFound, result.ErrorCode);
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // VALID TOKEN REVOCATION
    // ═══════════════════════════════════════════════════════════════════════════

    [Fact]
    public async Task SignOut_ValidToken_CallsRevokeSessionAsync()
    {
        (User? user, Account _) = await _fixture.SeedUserAsync();
        Session session = await SeedSessionAsync(user, "valid-token-123");
        SessionDeleteInput? captured = null;

        _sessionMock
            .Setup(s => s.RevokeSessionAsync(It.IsAny<SessionDeleteInput>(), It.IsAny<CancellationToken>()))
            .Callback<SessionDeleteInput, CancellationToken>((i, _) => captured = i)
            .ReturnsAsync(Result.Success());

        Result result = await _sut.SignOut(new SignOutInput { Token = "valid-token-123" });

        Assert.True(result.IsSuccess);
        Assert.NotNull(captured);
        Assert.Equal("valid-token-123", captured!.Token);
        Assert.Equal(user.Id, captured.User.Id);
    }

    [Fact]
    public async Task SignOut_RevokeSessionFails_PropagatesFailure()
    {
        (User? user, Account _) = await _fixture.SeedUserAsync();
        await SeedSessionAsync(user, "fail-token");

        _sessionMock
            .Setup(s => s.RevokeSessionAsync(It.IsAny<SessionDeleteInput>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(Result.Failure(AuthErrors.System.InternalError, "Cache unavailable"));

        Result result = await _sut.SignOut(new SignOutInput { Token = "fail-token" });

        Assert.False(result.IsSuccess);
        Assert.Equal(AuthErrors.System.InternalError, result.ErrorCode);
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // TOKEN MANIPULATION — Attacker modifying characters
    // ═══════════════════════════════════════════════════════════════════════════

    [Fact]
    public async Task SignOut_TokenOffByOneChar_ReturnsSessionNotFound()
    {
        (User? user, Account _) = await _fixture.SeedUserAsync();
        await SeedSessionAsync(user, "exact-token-value");

        Result result = await _sut.SignOut(new SignOutInput { Token = "exact-token-valuX" });

        Assert.False(result.IsSuccess);
        Assert.Equal(AuthErrors.Session.SessionNotFound, result.ErrorCode);
    }

    [Fact]
    public async Task SignOut_TokenWithTrailingNull_ReturnsSessionNotFound()
    {
        (User? user, Account _) = await _fixture.SeedUserAsync();
        await SeedSessionAsync(user, "clean-token");

        Result result = await _sut.SignOut(new SignOutInput { Token = "clean-token\0" });

        Assert.False(result.IsSuccess);
        Assert.Equal(AuthErrors.Session.SessionNotFound, result.ErrorCode);
    }

    [Fact]
    public async Task SignOut_TokenWithSqlInjection_ReturnsSessionNotFound()
    {
        Result result = await _sut.SignOut(new SignOutInput { Token = "'; DROP TABLE Sessions;--" });

        Assert.False(result.IsSuccess);
        Assert.Equal(AuthErrors.Session.SessionNotFound, result.ErrorCode);
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // DOUBLE SIGN-OUT — Idempotency
    // ═══════════════════════════════════════════════════════════════════════════

    [Fact]
    public async Task SignOut_SameTokenTwice_SecondCallReturnsSessionNotFound()
    {
        (User? user, Account _) = await _fixture.SeedUserAsync();
        await SeedSessionAsync(user, "one-time-token");

        _sessionMock
            .Setup(s => s.RevokeSessionAsync(It.IsAny<SessionDeleteInput>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(Result.Success())
            .Callback<SessionDeleteInput, CancellationToken>(async (i, _) =>
            {
                // Simulate the session being deleted from DB by the service
                Session? dbSession = await _fixture.DbContext.Sessions.FirstOrDefaultAsync(s => s.Token == i.Token);
                if (dbSession is not null)
                {
                    _fixture.DbContext.Sessions.Remove(dbSession);
                    await _fixture.DbContext.SaveChangesAsync();
                }
            });

        Result first = await _sut.SignOut(new SignOutInput { Token = "one-time-token" });
        Result second = await _sut.SignOut(new SignOutInput { Token = "one-time-token" });

        Assert.True(first.IsSuccess);
        Assert.False(second.IsSuccess);
        Assert.Equal(AuthErrors.Session.SessionNotFound, second.ErrorCode);
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // EXTREMELY LONG TOKEN — DoS via oversized token
    // ═══════════════════════════════════════════════════════════════════════════

    [Fact]
    public async Task SignOut_VeryLongToken_ReturnsSessionNotFound()
    {
        var megaToken = new string('A', 1_000_000); // 1MB token

        Result result = await _sut.SignOut(new SignOutInput { Token = megaToken });

        Assert.False(result.IsSuccess);
        Assert.Equal(AuthErrors.Session.SessionNotFound, result.ErrorCode);
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // SESSION INCLUDES USER — Required for registry cleanup
    // ═══════════════════════════════════════════════════════════════════════════

    [Fact]
    public async Task SignOut_SessionUserIsLoadedForRevokeInput()
    {
        (User? user, Account _) = await _fixture.SeedUserAsync(email: "loadtest@test.com");
        await SeedSessionAsync(user, "user-token");

        _sessionMock
            .Setup(s => s.RevokeSessionAsync(It.Is<SessionDeleteInput>(
                i => i.User != null && i.User.Id == user.Id)))
            .ReturnsAsync(Result.Success());

        Result result = await _sut.SignOut(new SignOutInput { Token = "user-token" });

        Assert.True(result.IsSuccess); _sessionMock.Verify(
            s => s.RevokeSessionAsync(It.Is<SessionDeleteInput>(i => i.User.Id == user.Id), It.IsAny<CancellationToken>()),
            Times.Once);
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // Helpers
    // ═══════════════════════════════════════════════════════════════════════════

    private async Task<Session> SeedSessionAsync(User user, string token)
    {
        var session = new Session
        {
            Id = Guid.CreateVersion7().ToString(),
            Token = token,
            ExpiresAt = DateTime.UtcNow.AddDays(7),
            UserId = user.Id,
            User = user,
            IpAddress = "127.0.0.1",
            UserAgent = "TestAgent/1.0",
            CreatedAt = DateTime.UtcNow,
            UpdatedAt = DateTime.UtcNow,
        };

        _fixture.DbContext.Sessions.Add(session);
        await _fixture.DbContext.SaveChangesAsync();
        return session;
    }
}
