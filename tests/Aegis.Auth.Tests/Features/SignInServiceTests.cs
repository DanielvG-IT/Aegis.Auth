using Aegis.Auth.Constants;
using Aegis.Auth.Entities;
using Aegis.Auth.Features.Sessions;
using Aegis.Auth.Features.SignIn;
using Aegis.Auth.Options;
using Aegis.Auth.Tests.Helpers;

using FluentAssertions;

using Moq;

namespace Aegis.Auth.Tests.Features;

/// <summary>
/// Adversarial test suite for SignInService.
/// Focus: timing-attack resistance, credential enumeration prevention,
/// boundary password validation, session creation invariants.
/// </summary>
public sealed class SignInServiceTests : IDisposable
{
  private readonly ServiceTestFixture _fixture;
  private readonly Mock<ISessionService> _sessionMock;
  private readonly SignInService _sut;

  public SignInServiceTests()
  {
    _fixture = new ServiceTestFixture();
    _sessionMock = new Mock<ISessionService>(MockBehavior.Strict);
    _sut = new SignInService(
        _fixture.Options,
        _fixture.LoggerFactory,
        _fixture.DbContext,
        _sessionMock.Object);
  }

  public void Dispose() => _fixture.Dispose();

  private static SignInEmailInput ValidInput(
      string email = "existing@test.com",
      string password = "ValidPass123!",
      bool rememberMe = true) => new()
      {
        Email = email,
        Password = password,
        RememberMe = rememberMe,
        UserAgent = "TestAgent/1.0",
        IpAddress = "10.0.0.1",
      };

  // ═══════════════════════════════════════════════════════════════════════════
  // FEATURE GATE
  // ═══════════════════════════════════════════════════════════════════════════

  [Fact]
  public async Task SignInEmail_WhenFeatureDisabled_ReturnsFeatureDisabled()
  {
    _fixture.Options.EmailAndPassword.Enabled = false;

    var result = await _sut.SignInEmail(ValidInput());

    result.IsSuccess.Should().BeFalse();
    result.ErrorCode.Should().Be(AuthErrors.System.FeatureDisabled);
  }

  [Fact]
  public async Task SignInEmail_WhenFeatureDisabled_ReturnsFeatureDisabledEvenIfUserExists()
  {
    _fixture.Options.EmailAndPassword.Enabled = false;
    await _fixture.SeedUserAsync();

    // Seed a user to show the outcome is independent of existing DB state
    var result = await _sut.SignInEmail(ValidInput());
    result.ErrorCode.Should().Be(AuthErrors.System.FeatureDisabled);
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // NULL / WHITESPACE EMAIL
  // ═══════════════════════════════════════════════════════════════════════════

  [Theory]
  [InlineData(null)]
  [InlineData("")]
  [InlineData("   ")]
  [InlineData("\t")]
  [InlineData("\r\n")]
  public async Task SignInEmail_WithNullOrWhitespaceEmail_ReturnsInvalidInput(string? email)
  {
    var result = await _sut.SignInEmail(ValidInput(email: email!));

    result.IsSuccess.Should().BeFalse();
    result.ErrorCode.Should().Be(AuthErrors.Validation.InvalidInput);
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // EMAIL FORMAT ATTACKS
  // ═══════════════════════════════════════════════════════════════════════════

  [Theory]
  [InlineData("not-an-email")]
  [InlineData("@missing-local.com")]
  [InlineData("missing-domain@")]
  [InlineData("double@@at.com")]
  [InlineData("<script>alert(1)</script>@xss.com")]
  public async Task SignInEmail_WithMalformedEmail_ReturnsInvalidInput(string email)
  {
    var result = await _sut.SignInEmail(ValidInput(email: email));

    result.IsSuccess.Should().BeFalse();
    result.ErrorCode.Should().Be(AuthErrors.Validation.InvalidInput);
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // CREDENTIAL ENUMERATION RESISTANCE
  // All invalid-credential paths must return the same error code to prevent
  // an attacker from distinguishing "user not found" from "wrong password".
  // ═══════════════════════════════════════════════════════════════════════════

  [Fact]
  public async Task SignInEmail_NonExistentUser_ReturnsInvalidEmailOrPassword()
  {
    var result = await _sut.SignInEmail(ValidInput(email: "ghost@test.com"));

    result.IsSuccess.Should().BeFalse();
    result.ErrorCode.Should().Be(AuthErrors.Identity.InvalidEmailOrPassword);
  }

  [Fact]
  public async Task SignInEmail_NonExistentUser_StillHashesPasswordForTimingSafety()
  {
    // The service should call Password.Hash even when user doesn't exist
    // to prevent timing-based user enumeration
    var hashCalled = false;
    _fixture.Options.EmailAndPassword.Password.Hash = password =>
    {
      hashCalled = true;
      return Task.FromResult($"hashed:{password}");
    };

    await _sut.SignInEmail(ValidInput(email: "ghost@test.com"));

    hashCalled.Should().BeTrue("Hash must be called for non-existent users to prevent timing attacks");
  }

  [Fact]
  public async Task SignInEmail_ExistingUserWrongPassword_ReturnsInvalidEmailOrPassword()
  {
    await _fixture.SeedUserAsync(email: "user@test.com", password: "CorrectPassword123!");

    var result = await _sut.SignInEmail(ValidInput(email: "user@test.com", password: "WrongPassword"));

    result.IsSuccess.Should().BeFalse();
    result.ErrorCode.Should().Be(AuthErrors.Identity.InvalidEmailOrPassword);
  }

  [Fact]
  public async Task SignInEmail_ErrorCodesMatch_ForNonExistentVsWrongPassword()
  {
    await _fixture.SeedUserAsync(email: "real@test.com", password: "RealPass123!");

    var nonExistent = await _sut.SignInEmail(ValidInput(email: "fake@test.com"));
    var wrongPassword = await _sut.SignInEmail(ValidInput(email: "real@test.com", password: "WrongOne"));

    // Both must return identical error codes — no information leakage
    nonExistent.ErrorCode.Should().Be(wrongPassword.ErrorCode,
        "error codes must be identical to prevent user enumeration");
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // OAUTH-ONLY USER — No credential account, but user exists
  // ═══════════════════════════════════════════════════════════════════════════

  [Fact]
  public async Task SignInEmail_OAuthOnlyUser_ReturnsInvalidEmailOrPassword()
  {
    // User exists via Google OAuth but has no "credential" provider
    await _fixture.SeedOAuthOnlyUserAsync(email: "oauth@test.com");

    var result = await _sut.SignInEmail(ValidInput(email: "oauth@test.com", password: "anything"));

    result.IsSuccess.Should().BeFalse();
    result.ErrorCode.Should().Be(AuthErrors.Identity.InvalidEmailOrPassword);
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // NULL / EMPTY PASSWORD HASH — Corrupted data attack
  // ═══════════════════════════════════════════════════════════════════════════

  [Fact]
  public async Task SignInEmail_UserWithNullPasswordHash_ReturnsInvalidEmailOrPassword()
  {
    await _fixture.SeedUserWithNullPasswordHashAsync(email: "nohash@test.com");

    var result = await _sut.SignInEmail(ValidInput(email: "nohash@test.com", password: "anything"));

    result.IsSuccess.Should().BeFalse();
    result.ErrorCode.Should().Be(AuthErrors.Identity.InvalidEmailOrPassword);
  }

  [Fact]
  public async Task SignInEmail_UserWithNullPasswordHash_StillHashesForTimingSafety()
  {
    await _fixture.SeedUserWithNullPasswordHashAsync(email: "nohash2@test.com");
    var hashCalled = false;
    _fixture.Options.EmailAndPassword.Password.Hash = p =>
    {
      hashCalled = true;
      return Task.FromResult($"hashed:{p}");
    };

    await _sut.SignInEmail(ValidInput(email: "nohash2@test.com", password: "anything"));

    hashCalled.Should().BeTrue("Hash must be called even with null password hash to prevent timing attacks");
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // EMAIL NORMALIZATION ON SIGN-IN
  // ═══════════════════════════════════════════════════════════════════════════

  [Fact]
  public async Task SignInEmail_UpperCaseEmail_MatchesLowerCaseUser()
  {
    await _fixture.SeedUserAsync(email: "casetest@test.com", password: "Password123!");
    SetupSessionMock();

    var result = await _sut.SignInEmail(ValidInput(email: "CaseTest@TEST.COM", password: "Password123!"));

    result.IsSuccess.Should().BeTrue();
  }

  [Fact]
  public async Task SignInEmail_WhitespaceAroundEmail_Trimmed()
  {
    await _fixture.SeedUserAsync(email: "trim@test.com", password: "Password123!");
    SetupSessionMock();

    var result = await _sut.SignInEmail(ValidInput(email: "  trim@test.com  ", password: "Password123!"));

    result.IsSuccess.Should().BeTrue();
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // SUCCESSFUL SIGN-IN — Happy path
  // ═══════════════════════════════════════════════════════════════════════════

  [Fact]
  public async Task SignInEmail_ValidCredentials_ReturnsSuccess()
  {
    await _fixture.SeedUserAsync(email: "valid@test.com", password: "CorrectPass!");
    SetupSessionMock();

    var result = await _sut.SignInEmail(ValidInput(email: "valid@test.com", password: "CorrectPass!"));

    result.IsSuccess.Should().BeTrue();
    result.Value!.User.Email.Should().Be("valid@test.com");
    result.Value.Session.Should().NotBeNull();
  }

  [Fact]
  public async Task SignInEmail_ValidCredentials_CallbackUrlPassedThrough()
  {
    await _fixture.SeedUserAsync(email: "callbackuser@test.com", password: "Password!");
    SetupSessionMock();

    var input = new SignInEmailInput
    {
      Email = "callbackuser@test.com",
      Password = "Password!",
      RememberMe = true,
      UserAgent = "TestAgent/1.0",
      IpAddress = "10.0.0.1",
      Callback = "https://app.example.com/dashboard"
    };

    var result = await _sut.SignInEmail(input);

    result.IsSuccess.Should().BeTrue();
    result.Value!.CallbackUrl.Should().Be("https://app.example.com/dashboard");
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // SESSION CREATION — DontRememberMe flag
  // ═══════════════════════════════════════════════════════════════════════════

  [Fact]
  public async Task SignInEmail_RememberMeTrue_SessionDontRememberMeIsFalse()
  {
    await _fixture.SeedUserAsync(email: "remember@test.com", password: "Password!");
    SessionCreateInput? captured = null;
    _sessionMock
        .Setup(s => s.CreateSessionAsync(It.IsAny<SessionCreateInput>()))
        .Callback<SessionCreateInput>(i => captured = i)
        .ReturnsAsync(Result<Session>.Success(CreateMockSession()));

    await _sut.SignInEmail(ValidInput(email: "remember@test.com", password: "Password!", rememberMe: true));

    captured.Should().NotBeNull();
    captured!.DontRememberMe.Should().BeFalse("RememberMe=true should set DontRememberMe=false");
  }

  [Fact]
  public async Task SignInEmail_RememberMeFalse_SessionDontRememberMeIsTrue()
  {
    await _fixture.SeedUserAsync(email: "forget@test.com", password: "Password!");
    SessionCreateInput? captured = null;
    _sessionMock
        .Setup(s => s.CreateSessionAsync(It.IsAny<SessionCreateInput>()))
        .Callback<SessionCreateInput>(i => captured = i)
        .ReturnsAsync(Result<Session>.Success(CreateMockSession()));

    await _sut.SignInEmail(ValidInput(email: "forget@test.com", password: "Password!", rememberMe: false));

    captured.Should().NotBeNull();
    captured!.DontRememberMe.Should().BeTrue("RememberMe=false should set DontRememberMe=true");
  }

  [Fact]
  public async Task SignInEmail_SessionCreationFails_ReturnsFailedToCreateSession()
  {
    await _fixture.SeedUserAsync(email: "sessionfail@test.com", password: "Password!");
    _sessionMock
        .Setup(s => s.CreateSessionAsync(It.IsAny<SessionCreateInput>()))
        .ReturnsAsync(Result<Session>.Failure(AuthErrors.System.InternalError, "Boom"));

    var result = await _sut.SignInEmail(ValidInput(email: "sessionfail@test.com", password: "Password!"));

    result.IsSuccess.Should().BeFalse();
    result.ErrorCode.Should().Be(AuthErrors.System.FailedToCreateSession);
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // SESSION RECEIVES CORRECT METADATA
  // ═══════════════════════════════════════════════════════════════════════════

  [Fact]
  public async Task SignInEmail_SessionInput_ContainsIpAndUserAgent()
  {
    await _fixture.SeedUserAsync(email: "meta@test.com", password: "Password!");
    SessionCreateInput? captured = null;
    _sessionMock
        .Setup(s => s.CreateSessionAsync(It.IsAny<SessionCreateInput>()))
        .Callback<SessionCreateInput>(i => captured = i)
        .ReturnsAsync(Result<Session>.Success(CreateMockSession()));

    var input = new SignInEmailInput
    {
      Email = "meta@test.com",
      Password = "Password!",
      RememberMe = true,
      UserAgent = "Mozilla/5.0 (Attacker)",
      IpAddress = "192.168.1.100",
    };

    await _sut.SignInEmail(input);

    captured.Should().NotBeNull();
    captured!.IpAddress.Should().Be("192.168.1.100");
    captured.UserAgent.Should().Be("Mozilla/5.0 (Attacker)");
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // EDGE CASES — Password verifier that always returns true (compromised hash)
  // ═══════════════════════════════════════════════════════════════════════════

  [Fact]
  public async Task SignInEmail_PasswordVerifierAlwaysTrue_SignsInSuccessfully()
  {
    // Simulates a misconfigured verifier — demonstrates trust in the delegate
    await _fixture.SeedUserAsync(email: "alwaystrue@test.com", password: "Anything");
    _fixture.Options.EmailAndPassword.Password.Verify = _ => Task.FromResult(true);
    SetupSessionMock();

    var result = await _sut.SignInEmail(ValidInput(email: "alwaystrue@test.com", password: "literally-anything"));

    result.IsSuccess.Should().BeTrue("the verifier accepted the password");
  }

  [Fact]
  public async Task SignInEmail_PasswordVerifierAlwaysFalse_AlwaysFails()
  {
    await _fixture.SeedUserAsync(email: "alwaysfalse@test.com", password: "CorrectPassword!");
    _fixture.Options.EmailAndPassword.Password.Verify = _ => Task.FromResult(false);

    var result = await _sut.SignInEmail(ValidInput(email: "alwaysfalse@test.com", password: "CorrectPassword!"));

    result.IsSuccess.Should().BeFalse();
    result.ErrorCode.Should().Be(AuthErrors.Identity.InvalidEmailOrPassword);
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // Helpers
  // ═══════════════════════════════════════════════════════════════════════════

  private Session CreateMockSession() => new()
  {
    Id = Guid.NewGuid().ToString(),
    Token = "test-session-token",
    ExpiresAt = DateTime.UtcNow.AddDays(7),
    UserId = "placeholder",
    IpAddress = "10.0.0.1",
    UserAgent = "TestAgent/1.0",
    CreatedAt = DateTime.UtcNow,
    UpdatedAt = DateTime.UtcNow,
  };

  private void SetupSessionMock()
  {
    _sessionMock
        .Setup(s => s.CreateSessionAsync(It.IsAny<SessionCreateInput>()))
        .ReturnsAsync(Result<Session>.Success(CreateMockSession()));
  }
}
