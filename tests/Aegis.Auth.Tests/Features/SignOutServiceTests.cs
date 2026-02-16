using Aegis.Auth.Constants;
using Aegis.Auth.Entities;
using Aegis.Auth.Features.Sessions;
using Aegis.Auth.Features.SignOut;
using Aegis.Auth.Tests.Helpers;

using FluentAssertions;

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
        _fixture.Options,
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

    var result = await _sut.SignOut(input);

    result.IsSuccess.Should().BeFalse();
    result.ErrorCode.Should().Be(AuthErrors.Session.SessionNotFound);
  }

  [Fact]
  public async Task SignOut_EmptyToken_ReturnsSessionNotFound()
  {
    var input = new SignOutInput { Token = string.Empty };

    var result = await _sut.SignOut(input);

    result.IsSuccess.Should().BeFalse();
    result.ErrorCode.Should().Be(AuthErrors.Session.SessionNotFound);
  }

  [Fact]
  public async Task SignOut_WhitespaceToken_ReturnsSessionNotFound()
  {
    var input = new SignOutInput { Token = "   " };

    var result = await _sut.SignOut(input);

    result.IsSuccess.Should().BeFalse();
    result.ErrorCode.Should().Be(AuthErrors.Session.SessionNotFound);
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // VALID TOKEN REVOCATION
  // ═══════════════════════════════════════════════════════════════════════════

  [Fact]
  public async Task SignOut_ValidToken_CallsRevokeSessionAsync()
  {
    var (user, _) = await _fixture.SeedUserAsync();
    var session = await SeedSessionAsync(user, "valid-token-123");
    SessionDeleteInput? captured = null;

    _sessionMock
        .Setup(s => s.RevokeSessionAsync(It.IsAny<SessionDeleteInput>()))
        .Callback<SessionDeleteInput>(i => captured = i)
        .ReturnsAsync(Result.Success());

    var result = await _sut.SignOut(new SignOutInput { Token = "valid-token-123" });

    result.IsSuccess.Should().BeTrue();
    captured.Should().NotBeNull();
    captured!.Token.Should().Be("valid-token-123");
    captured.User.Id.Should().Be(user.Id);
  }

  [Fact]
  public async Task SignOut_RevokeSessionFails_PropagatesFailure()
  {
    var (user, _) = await _fixture.SeedUserAsync();
    await SeedSessionAsync(user, "fail-token");

    _sessionMock
        .Setup(s => s.RevokeSessionAsync(It.IsAny<SessionDeleteInput>()))
        .ReturnsAsync(Result.Failure(AuthErrors.System.InternalError, "Cache unavailable"));

    var result = await _sut.SignOut(new SignOutInput { Token = "fail-token" });

    result.IsSuccess.Should().BeFalse();
    result.ErrorCode.Should().Be(AuthErrors.System.InternalError);
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // TOKEN MANIPULATION — Attacker modifying characters
  // ═══════════════════════════════════════════════════════════════════════════

  [Fact]
  public async Task SignOut_TokenOffByOneChar_ReturnsSessionNotFound()
  {
    var (user, _) = await _fixture.SeedUserAsync();
    await SeedSessionAsync(user, "exact-token-value");

    var result = await _sut.SignOut(new SignOutInput { Token = "exact-token-valuX" });

    result.IsSuccess.Should().BeFalse();
    result.ErrorCode.Should().Be(AuthErrors.Session.SessionNotFound);
  }

  [Fact]
  public async Task SignOut_TokenWithTrailingNull_ReturnsSessionNotFound()
  {
    var (user, _) = await _fixture.SeedUserAsync();
    await SeedSessionAsync(user, "clean-token");

    var result = await _sut.SignOut(new SignOutInput { Token = "clean-token\0" });

    result.IsSuccess.Should().BeFalse();
    result.ErrorCode.Should().Be(AuthErrors.Session.SessionNotFound);
  }

  [Fact]
  public async Task SignOut_TokenWithSqlInjection_ReturnsSessionNotFound()
  {
    var result = await _sut.SignOut(new SignOutInput { Token = "'; DROP TABLE Sessions;--" });

    result.IsSuccess.Should().BeFalse();
    result.ErrorCode.Should().Be(AuthErrors.Session.SessionNotFound);
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // DOUBLE SIGN-OUT — Idempotency
  // ═══════════════════════════════════════════════════════════════════════════

  [Fact]
  public async Task SignOut_SameTokenTwice_SecondCallReturnsSessionNotFound()
  {
    var (user, _) = await _fixture.SeedUserAsync();
    await SeedSessionAsync(user, "one-time-token");

    _sessionMock
        .Setup(s => s.RevokeSessionAsync(It.IsAny<SessionDeleteInput>()))
        .ReturnsAsync(Result.Success())
        .Callback<SessionDeleteInput>(async i =>
        {
          // Simulate the session being deleted from DB by the service
          var dbSession = await _fixture.DbContext.Sessions.FirstOrDefaultAsync(s => s.Token == i.Token);
          if (dbSession is not null)
          {
            _fixture.DbContext.Sessions.Remove(dbSession);
            await _fixture.DbContext.SaveChangesAsync();
          }
        });

    var first = await _sut.SignOut(new SignOutInput { Token = "one-time-token" });
    var second = await _sut.SignOut(new SignOutInput { Token = "one-time-token" });

    first.IsSuccess.Should().BeTrue();
    second.IsSuccess.Should().BeFalse();
    second.ErrorCode.Should().Be(AuthErrors.Session.SessionNotFound);
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // EXTREMELY LONG TOKEN — DoS via oversized token
  // ═══════════════════════════════════════════════════════════════════════════

  [Fact]
  public async Task SignOut_VeryLongToken_ReturnsSessionNotFound()
  {
    var megaToken = new string('A', 1_000_000); // 1MB token

    var result = await _sut.SignOut(new SignOutInput { Token = megaToken });

    result.IsSuccess.Should().BeFalse();
    result.ErrorCode.Should().Be(AuthErrors.Session.SessionNotFound);
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // SESSION INCLUDES USER — Required for registry cleanup
  // ═══════════════════════════════════════════════════════════════════════════

  [Fact]
  public async Task SignOut_SessionUserIsLoadedForRevokeInput()
  {
    var (user, _) = await _fixture.SeedUserAsync(email: "loadtest@test.com");
    await SeedSessionAsync(user, "user-token");

    _sessionMock
        .Setup(s => s.RevokeSessionAsync(It.Is<SessionDeleteInput>(
            i => i.User != null && i.User.Id == user.Id)))
        .ReturnsAsync(Result.Success());

    var result = await _sut.SignOut(new SignOutInput { Token = "user-token" });

    result.IsSuccess.Should().BeTrue();
    _sessionMock.Verify(
        s => s.RevokeSessionAsync(It.Is<SessionDeleteInput>(i => i.User.Id == user.Id)),
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
