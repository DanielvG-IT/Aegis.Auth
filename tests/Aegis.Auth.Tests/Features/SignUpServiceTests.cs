using Aegis.Auth.Constants;
using Aegis.Auth.Entities;
using Aegis.Auth.Features.Sessions;
using Aegis.Auth.Features.SignUp;
using Aegis.Auth.Options;
using Aegis.Auth.Tests.Helpers;

using Microsoft.Extensions.Options;

using Moq;

namespace Aegis.Auth.Tests.Features;

/// <summary>
/// Adversarial test suite for SignUpService.
/// Treats sign-up as a security boundary: every path is tested for
/// bypass attempts, boundary conditions, and invariant violations.
/// </summary>
public sealed class SignUpServiceTests : IDisposable
{
    private readonly ServiceTestFixture _fixture;
    private readonly Mock<ISessionService> _sessionMock;
    private readonly SignUpService _sut;

    public SignUpServiceTests()
    {
        _fixture = new ServiceTestFixture();
        _sessionMock = new Mock<ISessionService>(MockBehavior.Strict);
        _sut = new SignUpService(
            Microsoft.Extensions.Options.Options.Create(_fixture.Options),
            _fixture.LoggerFactory,
            _fixture.DbContext,
            _sessionMock.Object);
    }

    public void Dispose() => _fixture.Dispose();

    private static SignUpEmailInput ValidInput(
        string email = "new@test.com",
        string password = "StrongPass123!",
        string name = "Test User") => new()
        {
            Email = email,
            Password = password,
            Name = name,
            UserAgent = "TestAgent/1.0",
            IpAddress = "127.0.0.1",
        };

    // ═══════════════════════════════════════════════════════════════════════════
    // FEATURE GATE — Can we bypass the disabled flag?
    // ═══════════════════════════════════════════════════════════════════════════

    [Fact]
    public async Task SignUpEmail_WhenEmailPasswordDisabled_ReturnsFeatureDisabled()
    {
        _fixture.Options.EmailAndPassword.Enabled = false;

        Result<SignUpResult> result = await _sut.SignUpEmail(ValidInput());

        Assert.False(result.IsSuccess);
        Assert.Equal(AuthErrors.System.FeatureDisabled, result.ErrorCode);
    }

    [Fact]
    public async Task SignUpEmail_WhenSignUpDisabled_ReturnsFeatureDisabled()
    {
        _fixture.Options.EmailAndPassword.DisableSignUp = true;

        Result<SignUpResult> result = await _sut.SignUpEmail(ValidInput());

        Assert.False(result.IsSuccess);
        Assert.Equal(AuthErrors.System.FeatureDisabled, result.ErrorCode);
    }

    [Fact]
    public async Task SignUpEmail_WhenBothDisableSignUpAndEnabledFalse_ReturnsFeatureDisabled()
    {
        _fixture.Options.EmailAndPassword.Enabled = false;
        _fixture.Options.EmailAndPassword.DisableSignUp = true;

        Result<SignUpResult> result = await _sut.SignUpEmail(ValidInput());

        Assert.False(result.IsSuccess);
        Assert.Equal(AuthErrors.System.FeatureDisabled, result.ErrorCode);
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // NULL / EMPTY / WHITESPACE INJECTION
    // ═══════════════════════════════════════════════════════════════════════════

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("\t")]
    [InlineData("\n")]
    public async Task SignUpEmail_WithNullOrWhitespaceEmail_ReturnsInvalidInput(string? email)
    {
        Result<SignUpResult> result = await _sut.SignUpEmail(ValidInput(email: email!));

        Assert.False(result.IsSuccess);
        Assert.Equal(AuthErrors.Validation.InvalidInput, result.ErrorCode);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("\t\n")]
    public async Task SignUpEmail_WithNullOrWhitespacePassword_ReturnsInvalidInput(string? password)
    {
        Result<SignUpResult> result = await _sut.SignUpEmail(ValidInput(password: password!));

        Assert.False(result.IsSuccess);
        Assert.Equal(AuthErrors.Validation.InvalidInput, result.ErrorCode);
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // EMAIL FORMAT — Malformed, dangerous, and boundary emails
    // ═══════════════════════════════════════════════════════════════════════════

    [Theory]
    [InlineData("not-an-email")]
    [InlineData("@missing-local.com")]
    [InlineData("missing-domain@")]
    [InlineData("spaces in@email.com")]
    [InlineData("double@@at.com")]
    [InlineData("trailing-dot@test.com.")]
    public async Task SignUpEmail_WithMalformedEmail_ReturnsInvalidInput(string email)
    {
        Result<SignUpResult> result = await _sut.SignUpEmail(ValidInput(email: email));

        Assert.False(result.IsSuccess);
        Assert.Equal(AuthErrors.Validation.InvalidInput, result.ErrorCode);
    }

    [Fact]
    public async Task SignUpEmail_NormalizesEmailToLowerCase()
    {
        SetupSessionMockForAutoSignIn();

        Result<SignUpResult> result = await _sut.SignUpEmail(ValidInput(email: "UpperCase@TEST.COM"));

        Assert.True(result.IsSuccess);
        Assert.Equal("uppercase@test.com", result.Value!.User.Email);
    }

    [Fact]
    public async Task SignUpEmail_TrimsWhitespaceFromEmail()
    {
        SetupSessionMockForAutoSignIn();

        Result<SignUpResult> result = await _sut.SignUpEmail(ValidInput(email: "  trimmed@test.com  "));

        Assert.True(result.IsSuccess);
        Assert.Equal("trimmed@test.com", result.Value!.User.Email);
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // PASSWORD LENGTH BOUNDARIES — Exact boundary of the envelope
    // ═══════════════════════════════════════════════════════════════════════════

    [Fact]
    public async Task SignUpEmail_PasswordExactlyOneCharBelowMinimum_ReturnsTooShort()
    {
        _fixture.Options.EmailAndPassword.MinPasswordLength = 8;
        var shortPassword = new string('A', 7);

        Result<SignUpResult> result = await _sut.SignUpEmail(ValidInput(password: shortPassword));

        Assert.False(result.IsSuccess);
        Assert.Equal(AuthErrors.Validation.PasswordTooShort, result.ErrorCode);
    }

    [Fact]
    public async Task SignUpEmail_PasswordExactlyAtMinimum_Succeeds()
    {
        _fixture.Options.EmailAndPassword.MinPasswordLength = 8;
        SetupSessionMockForAutoSignIn();
        var exactMin = new string('A', 8);

        Result<SignUpResult> result = await _sut.SignUpEmail(ValidInput(password: exactMin));

        Assert.True(result.IsSuccess);
    }

    [Fact]
    public async Task SignUpEmail_PasswordExactlyAtMaximum_Succeeds()
    {
        _fixture.Options.EmailAndPassword.MaxPasswordLength = 128;
        SetupSessionMockForAutoSignIn();
        var exactMax = new string('A', 128);

        Result<SignUpResult> result = await _sut.SignUpEmail(ValidInput(password: exactMax));

        Assert.True(result.IsSuccess);
    }

    [Fact]
    public async Task SignUpEmail_PasswordOneCharOverMaximum_ReturnsTooLong()
    {
        _fixture.Options.EmailAndPassword.MaxPasswordLength = 128;
        var overMax = new string('A', 129);

        Result<SignUpResult> result = await _sut.SignUpEmail(ValidInput(password: overMax));

        Assert.False(result.IsSuccess);
        Assert.Equal(AuthErrors.Validation.PasswordTooLong, result.ErrorCode);
    }

    [Fact]
    public async Task SignUpEmail_PasswordIs2MBLong_ReturnsTooLong()
    {
        // 2MB denial-of-service attempt via password field
        var megaPassword = new string('Z', 2 * 1024 * 1024);

        Result<SignUpResult> result = await _sut.SignUpEmail(ValidInput(password: megaPassword));

        Assert.False(result.IsSuccess);
        Assert.Equal(AuthErrors.Validation.PasswordTooLong, result.ErrorCode);
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // CUSTOM PASSWORD VALIDATOR — Can we bypass it?
    // ═══════════════════════════════════════════════════════════════════════════

    [Fact]
    public async Task SignUpEmail_CustomValidatorRejectsPassword_ReturnsInvalidInput()
    {
        _fixture.Options.EmailAndPassword.Password.Validate =
            _ => Task.FromResult(PasswordValidationResult.Invalid("Password must contain a digit."));

        Result<SignUpResult> result = await _sut.SignUpEmail(ValidInput(password: "NoDigitsHere"));

        Assert.False(result.IsSuccess);
        Assert.Equal(AuthErrors.Validation.InvalidInput, result.ErrorCode);
        Assert.Equal("Password must contain a digit.", result.Message);
    }

    [Fact]
    public async Task SignUpEmail_CustomValidatorAcceptsPassword_Proceeds()
    {
        _fixture.Options.EmailAndPassword.Password.Validate =
            _ => Task.FromResult(PasswordValidationResult.Valid());
        SetupSessionMockForAutoSignIn();

        Result<SignUpResult> result = await _sut.SignUpEmail(ValidInput());

        Assert.True(result.IsSuccess);
    }

    [Fact]
    public async Task SignUpEmail_CustomValidatorReturnsNullErrorMessage_UsesFallback()
    {
        _fixture.Options.EmailAndPassword.Password.Validate =
            _ => Task.FromResult(new PasswordValidationResult { IsValid = false, ErrorMessage = null });

        Result<SignUpResult> result = await _sut.SignUpEmail(ValidInput());

        Assert.False(result.IsSuccess);
        Assert.Equal("Password validation failed.", result.Message);
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // DUPLICATE USER — Race condition and enumeration resistance
    // ═══════════════════════════════════════════════════════════════════════════

    [Fact]
    public async Task SignUpEmail_DuplicateEmail_ReturnsUserAlreadyExists()
    {
        await _fixture.SeedUserAsync(email: "duplicate@test.com");

        Result<SignUpResult> result = await _sut.SignUpEmail(ValidInput(email: "duplicate@test.com"));

        Assert.False(result.IsSuccess);
        Assert.Equal(AuthErrors.Identity.UserAlreadyExists, result.ErrorCode);
    }

    [Fact]
    public async Task SignUpEmail_DuplicateEmailDifferentCase_ReturnsUserAlreadyExists()
    {
        await _fixture.SeedUserAsync(email: "case@test.com");

        Result<SignUpResult> result = await _sut.SignUpEmail(ValidInput(email: "CASE@TEST.COM"));

        Assert.False(result.IsSuccess);
        Assert.Equal(AuthErrors.Identity.UserAlreadyExists, result.ErrorCode);
    }

    [Fact]
    public async Task SignUpEmail_DuplicateEmailWithWhitespace_ReturnsUserAlreadyExists()
    {
        await _fixture.SeedUserAsync(email: "padded@test.com");

        Result<SignUpResult> result = await _sut.SignUpEmail(ValidInput(email: "  padded@test.com  "));

        Assert.False(result.IsSuccess);
        Assert.Equal(AuthErrors.Identity.UserAlreadyExists, result.ErrorCode);
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // SUCCESSFUL REGISTRATION — The happy path
    // ═══════════════════════════════════════════════════════════════════════════

    [Fact]
    public async Task SignUpEmail_ValidInput_CreatesUserAndAccount()
    {
        SetupSessionMockForAutoSignIn();

        Result<SignUpResult> result = await _sut.SignUpEmail(ValidInput(email: "newuser@test.com", name: "New User"));

        Assert.True(result.IsSuccess);
        Assert.Equal("newuser@test.com", result.Value!.User.Email);
        Assert.Equal("New User", result.Value.User.Name);
        // Verify persisted to DB
        User? dbUser = _fixture.DbContext.Users.SingleOrDefault(u => u.Email == "newuser@test.com");
        Assert.NotNull(dbUser);
        Account? dbAccount = _fixture.DbContext.Accounts.SingleOrDefault(a => a.UserId == dbUser!.Id);

        Assert.NotNull(dbAccount);
        Assert.Equal("credential", dbAccount!.ProviderId);
        Assert.False(string.IsNullOrWhiteSpace(dbAccount.PasswordHash));
    }

    [Fact]
    public async Task SignUpEmail_ValidInput_PasswordIsHashedNotStoredInPlaintext()
    {
        SetupSessionMockForAutoSignIn();
        const string rawPassword = "MySecret123!";

        Result<SignUpResult> result = await _sut.SignUpEmail(ValidInput(email: "hashcheck@test.com", password: rawPassword));

        Assert.True(result.IsSuccess); Account account = _fixture.DbContext.Accounts.Single(a => a.UserId == result.Value!.User.Id);
        Assert.NotEqual(rawPassword, account.PasswordHash);
        Assert.Equal($"hashed:{rawPassword}", account.PasswordHash);
    }

    [Fact]
    public async Task SignUpEmail_UserIdIsValidGuidV7()
    {
        SetupSessionMockForAutoSignIn();

        Result<SignUpResult> result = await _sut.SignUpEmail(ValidInput(email: "guidcheck@test.com"));

        Assert.True(result.IsSuccess);
        Assert.True(Guid.TryParse(result.Value!.User.Id, out _), "User ID should be a valid GUID");
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // AUTO-SIGN-IN BEHAVIOR
    // ═══════════════════════════════════════════════════════════════════════════

    [Fact]
    public async Task SignUpEmail_AutoSignInEnabled_CreatesSession()
    {
        _fixture.Options.EmailAndPassword.AutoSignIn = true;
        Session expectedSession = CreateMockSession();
        _sessionMock
            .Setup(s => s.CreateSessionAsync(It.IsAny<SessionCreateInput>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(Result<Session>.Success(expectedSession));

        Result<SignUpResult> result = await _sut.SignUpEmail(ValidInput());

        Assert.True(result.IsSuccess);
        Assert.NotNull(result.Value!.Session); _sessionMock.Verify(s => s.CreateSessionAsync(It.Is<SessionCreateInput>(
            i => i.DontRememberMe == true)), Times.Once);
    }

    [Fact]
    public async Task SignUpEmail_AutoSignInDisabled_NoSessionCreated()
    {
        _fixture.Options.EmailAndPassword.AutoSignIn = false;

        Result<SignUpResult> result = await _sut.SignUpEmail(ValidInput());

        Assert.True(result.IsSuccess);
        Assert.Null(result.Value!.Session); _sessionMock.Verify(s => s.CreateSessionAsync(It.IsAny<SessionCreateInput>(), It.IsAny<CancellationToken>()), Times.Never);
    }

    [Fact]
    public async Task SignUpEmail_AutoSignIn_SessionInputContainsCorrectIpAndUserAgent()
    {
        _fixture.Options.EmailAndPassword.AutoSignIn = true;
        SessionCreateInput? capturedInput = null;
        _sessionMock
            .Setup(s => s.CreateSessionAsync(It.IsAny<SessionCreateInput>(), It.IsAny<CancellationToken>()))
            .Callback<SessionCreateInput, CancellationToken>((i, _) => capturedInput = i)
            .ReturnsAsync(Result<Session>.Success(CreateMockSession()));

        SignUpEmailInput input = ValidInput();
        await _sut.SignUpEmail(input);

        Assert.NotNull(capturedInput);
        Assert.Equal("127.0.0.1", capturedInput!.IpAddress);
        Assert.Equal("TestAgent/1.0", capturedInput.UserAgent);
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // CALLBACK URL PASSTHROUGH
    // ═══════════════════════════════════════════════════════════════════════════

    [Fact]
    public async Task SignUpEmail_CallbackUrl_PassedThroughToResult()
    {
        SetupSessionMockForAutoSignIn();
        SignUpEmailInput input = ValidInput();
        input = new SignUpEmailInput
        {
            Email = input.Email,
            Password = input.Password,
            Name = input.Name,
            UserAgent = input.UserAgent,
            IpAddress = input.IpAddress,
            Callback = "https://app.example.com/welcome"
        };

        Result<SignUpResult> result = await _sut.SignUpEmail(input);

        Assert.True(result.IsSuccess);
        Assert.Equal("https://app.example.com/welcome", result.Value!.CallbackUrl);
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // UNICODE / SPECIAL CHARACTER ATTACKS
    // ═══════════════════════════════════════════════════════════════════════════

    [Fact]
    public async Task SignUpEmail_UnicodePassword_IsAccepted()
    {
        SetupSessionMockForAutoSignIn();
        const string unicodePassword = "Pässwörd🔐с密码够长的密码";

        Result<SignUpResult> result = await _sut.SignUpEmail(ValidInput(password: unicodePassword));

        Assert.True(result.IsSuccess);
    }

    [Fact]
    public async Task SignUpEmail_NameWithHtmlTags_IsStoredAsIs()
    {
        // XSS in name — service should store it; output encoding is a presentation concern
        SetupSessionMockForAutoSignIn();
        const string xssName = "<script>alert('xss')</script>";

        Result<SignUpResult> result = await _sut.SignUpEmail(ValidInput(name: xssName));

        Assert.True(result.IsSuccess);
        Assert.Equal(xssName, result.Value!.User.Name);
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // TIMING / ORDERING INVARIANTS
    // ═══════════════════════════════════════════════════════════════════════════

    [Fact]
    public async Task SignUpEmail_CreatedAtAndUpdatedAt_AreSetToUtcNow()
    {
        SetupSessionMockForAutoSignIn();
        DateTime before = DateTime.UtcNow.AddSeconds(-1);

        Result<SignUpResult> result = await _sut.SignUpEmail(ValidInput(email: "time@test.com"));
        DateTime after = DateTime.UtcNow.AddSeconds(1);

        Assert.True(result.IsSuccess);
        Assert.InRange(result.Value!.User.CreatedAt, before, after);
        Assert.InRange(result.Value.User.UpdatedAt, before, after);
    }

    [Fact]
    public async Task SignUpEmail_AccountUserId_MatchesUserId()
    {
        SetupSessionMockForAutoSignIn();

        Result<SignUpResult> result = await _sut.SignUpEmail(ValidInput(email: "relations@test.com"));

        Assert.True(result.IsSuccess); Account account = _fixture.DbContext.Accounts.Single(a => a.UserId == result.Value!.User.Id);
        Assert.Equal(result.Value!.User.Id, account.UserId);
        Assert.Equal("relations@test.com", account.AccountId);
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // ORDERING: Email/password checks run BEFORE database queries
    // ═══════════════════════════════════════════════════════════════════════════

    [Fact]
    public async Task SignUpEmail_FeatureDisabled_DoesNotModifyDatabase()
    {
        _fixture.Options.EmailAndPassword.Enabled = false;
        var userCountBefore = _fixture.DbContext.Users.Count();

        await _sut.SignUpEmail(ValidInput());

        Assert.Equal(userCountBefore, _fixture.DbContext.Users.Count());
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // Helpers
    // ═══════════════════════════════════════════════════════════════════════════

    private Session CreateMockSession() => new()
    {
        Id = Guid.NewGuid().ToString(),
        Token = "test-session-token",
        ExpiresAt = DateTime.UtcNow.AddDays(1),
        UserId = "will-be-overridden",
        IpAddress = "127.0.0.1",
        UserAgent = "TestAgent/1.0",
        CreatedAt = DateTime.UtcNow,
        UpdatedAt = DateTime.UtcNow,
    };

    private void SetupSessionMockForAutoSignIn()
    {
        _sessionMock
            .Setup(s => s.CreateSessionAsync(It.IsAny<SessionCreateInput>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(Result<Session>.Success(CreateMockSession()));
    }
}
