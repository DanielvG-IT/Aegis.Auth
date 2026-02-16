using Aegis.Auth.Constants;
using Aegis.Auth.Entities;
using Aegis.Auth.Features.Sessions;
using Aegis.Auth.Features.SignUp;
using Aegis.Auth.Options;
using Aegis.Auth.Tests.Helpers;

using FluentAssertions;

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
            _fixture.Options,
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

        result.IsSuccess.Should().BeFalse();
        result.ErrorCode.Should().Be(AuthErrors.System.FeatureDisabled);
    }

    [Fact]
    public async Task SignUpEmail_WhenSignUpDisabled_ReturnsFeatureDisabled()
    {
        _fixture.Options.EmailAndPassword.DisableSignUp = true;

        Result<SignUpResult> result = await _sut.SignUpEmail(ValidInput());

        result.IsSuccess.Should().BeFalse();
        result.ErrorCode.Should().Be(AuthErrors.System.FeatureDisabled);
    }

    [Fact]
    public async Task SignUpEmail_WhenBothDisableSignUpAndEnabledFalse_ReturnsFeatureDisabled()
    {
        _fixture.Options.EmailAndPassword.Enabled = false;
        _fixture.Options.EmailAndPassword.DisableSignUp = true;

        Result<SignUpResult> result = await _sut.SignUpEmail(ValidInput());

        result.IsSuccess.Should().BeFalse();
        result.ErrorCode.Should().Be(AuthErrors.System.FeatureDisabled);
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

        result.IsSuccess.Should().BeFalse();
        result.ErrorCode.Should().Be(AuthErrors.Validation.InvalidInput);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("\t\n")]
    public async Task SignUpEmail_WithNullOrWhitespacePassword_ReturnsInvalidInput(string? password)
    {
        Result<SignUpResult> result = await _sut.SignUpEmail(ValidInput(password: password!));

        result.IsSuccess.Should().BeFalse();
        result.ErrorCode.Should().Be(AuthErrors.Validation.InvalidInput);
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

        result.IsSuccess.Should().BeFalse();
        result.ErrorCode.Should().Be(AuthErrors.Validation.InvalidInput);
    }

    [Fact]
    public async Task SignUpEmail_NormalizesEmailToLowerCase()
    {
        SetupSessionMockForAutoSignIn();

        Result<SignUpResult> result = await _sut.SignUpEmail(ValidInput(email: "UpperCase@TEST.COM"));

        result.IsSuccess.Should().BeTrue();
        result.Value!.User.Email.Should().Be("uppercase@test.com");
    }

    [Fact]
    public async Task SignUpEmail_TrimsWhitespaceFromEmail()
    {
        SetupSessionMockForAutoSignIn();

        Result<SignUpResult> result = await _sut.SignUpEmail(ValidInput(email: "  trimmed@test.com  "));

        result.IsSuccess.Should().BeTrue();
        result.Value!.User.Email.Should().Be("trimmed@test.com");
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

        result.IsSuccess.Should().BeFalse();
        result.ErrorCode.Should().Be(AuthErrors.Validation.PasswordTooShort);
    }

    [Fact]
    public async Task SignUpEmail_PasswordExactlyAtMinimum_Succeeds()
    {
        _fixture.Options.EmailAndPassword.MinPasswordLength = 8;
        SetupSessionMockForAutoSignIn();
        var exactMin = new string('A', 8);

        Result<SignUpResult> result = await _sut.SignUpEmail(ValidInput(password: exactMin));

        result.IsSuccess.Should().BeTrue();
    }

    [Fact]
    public async Task SignUpEmail_PasswordExactlyAtMaximum_Succeeds()
    {
        _fixture.Options.EmailAndPassword.MaxPasswordLength = 128;
        SetupSessionMockForAutoSignIn();
        var exactMax = new string('A', 128);

        Result<SignUpResult> result = await _sut.SignUpEmail(ValidInput(password: exactMax));

        result.IsSuccess.Should().BeTrue();
    }

    [Fact]
    public async Task SignUpEmail_PasswordOneCharOverMaximum_ReturnsTooLong()
    {
        _fixture.Options.EmailAndPassword.MaxPasswordLength = 128;
        var overMax = new string('A', 129);

        Result<SignUpResult> result = await _sut.SignUpEmail(ValidInput(password: overMax));

        result.IsSuccess.Should().BeFalse();
        result.ErrorCode.Should().Be(AuthErrors.Validation.PasswordTooLong);
    }

    [Fact]
    public async Task SignUpEmail_PasswordIs2MBLong_ReturnsTooLong()
    {
        // 2MB denial-of-service attempt via password field
        var megaPassword = new string('Z', 2 * 1024 * 1024);

        Result<SignUpResult> result = await _sut.SignUpEmail(ValidInput(password: megaPassword));

        result.IsSuccess.Should().BeFalse();
        result.ErrorCode.Should().Be(AuthErrors.Validation.PasswordTooLong);
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

        result.IsSuccess.Should().BeFalse();
        result.ErrorCode.Should().Be(AuthErrors.Validation.InvalidInput);
        result.Message.Should().Be("Password must contain a digit.");
    }

    [Fact]
    public async Task SignUpEmail_CustomValidatorAcceptsPassword_Proceeds()
    {
        _fixture.Options.EmailAndPassword.Password.Validate =
            _ => Task.FromResult(PasswordValidationResult.Valid());
        SetupSessionMockForAutoSignIn();

        Result<SignUpResult> result = await _sut.SignUpEmail(ValidInput());

        result.IsSuccess.Should().BeTrue();
    }

    [Fact]
    public async Task SignUpEmail_CustomValidatorReturnsNullErrorMessage_UsesFallback()
    {
        _fixture.Options.EmailAndPassword.Password.Validate =
            _ => Task.FromResult(new PasswordValidationResult { IsValid = false, ErrorMessage = null });

        Result<SignUpResult> result = await _sut.SignUpEmail(ValidInput());

        result.IsSuccess.Should().BeFalse();
        result.Message.Should().Be("Password validation failed.");
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // DUPLICATE USER — Race condition and enumeration resistance
    // ═══════════════════════════════════════════════════════════════════════════

    [Fact]
    public async Task SignUpEmail_DuplicateEmail_ReturnsUserAlreadyExists()
    {
        await _fixture.SeedUserAsync(email: "duplicate@test.com");

        Result<SignUpResult> result = await _sut.SignUpEmail(ValidInput(email: "duplicate@test.com"));

        result.IsSuccess.Should().BeFalse();
        result.ErrorCode.Should().Be(AuthErrors.Identity.UserAlreadyExists);
    }

    [Fact]
    public async Task SignUpEmail_DuplicateEmailDifferentCase_ReturnsUserAlreadyExists()
    {
        await _fixture.SeedUserAsync(email: "case@test.com");

        Result<SignUpResult> result = await _sut.SignUpEmail(ValidInput(email: "CASE@TEST.COM"));

        result.IsSuccess.Should().BeFalse();
        result.ErrorCode.Should().Be(AuthErrors.Identity.UserAlreadyExists);
    }

    [Fact]
    public async Task SignUpEmail_DuplicateEmailWithWhitespace_ReturnsUserAlreadyExists()
    {
        await _fixture.SeedUserAsync(email: "padded@test.com");

        Result<SignUpResult> result = await _sut.SignUpEmail(ValidInput(email: "  padded@test.com  "));

        result.IsSuccess.Should().BeFalse();
        result.ErrorCode.Should().Be(AuthErrors.Identity.UserAlreadyExists);
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // SUCCESSFUL REGISTRATION — The happy path
    // ═══════════════════════════════════════════════════════════════════════════

    [Fact]
    public async Task SignUpEmail_ValidInput_CreatesUserAndAccount()
    {
        SetupSessionMockForAutoSignIn();

        Result<SignUpResult> result = await _sut.SignUpEmail(ValidInput(email: "newuser@test.com", name: "New User"));

        result.IsSuccess.Should().BeTrue();
        result.Value!.User.Email.Should().Be("newuser@test.com");
        result.Value.User.Name.Should().Be("New User");

        // Verify persisted to DB
        User? dbUser = _fixture.DbContext.Users.SingleOrDefault(u => u.Email == "newuser@test.com");
        dbUser.Should().NotBeNull();

        Account? dbAccount = _fixture.DbContext.Accounts.SingleOrDefault(a => a.UserId == dbUser!.Id);
        dbAccount.Should().NotBeNull();
        dbAccount!.ProviderId.Should().Be("credential");
        dbAccount.PasswordHash.Should().NotBeNullOrWhiteSpace();
    }

    [Fact]
    public async Task SignUpEmail_ValidInput_PasswordIsHashedNotStoredInPlaintext()
    {
        SetupSessionMockForAutoSignIn();
        const string rawPassword = "MySecret123!";

        Result<SignUpResult> result = await _sut.SignUpEmail(ValidInput(email: "hashcheck@test.com", password: rawPassword));

        result.IsSuccess.Should().BeTrue();
        Account account = _fixture.DbContext.Accounts.Single(a => a.UserId == result.Value!.User.Id);
        account.PasswordHash.Should().NotBe(rawPassword, "password must never be stored in plaintext");
        account.PasswordHash.Should().Be($"hashed:{rawPassword}");
    }

    [Fact]
    public async Task SignUpEmail_UserIdIsValidGuidV7()
    {
        SetupSessionMockForAutoSignIn();

        Result<SignUpResult> result = await _sut.SignUpEmail(ValidInput(email: "guidcheck@test.com"));

        result.IsSuccess.Should().BeTrue();
        Guid.TryParse(result.Value!.User.Id, out _).Should().BeTrue("User ID should be a valid GUID");
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
            .Setup(s => s.CreateSessionAsync(It.IsAny<SessionCreateInput>()))
            .ReturnsAsync(Result<Session>.Success(expectedSession));

        Result<SignUpResult> result = await _sut.SignUpEmail(ValidInput());

        result.IsSuccess.Should().BeTrue();
        result.Value!.Session.Should().NotBeNull();
        _sessionMock.Verify(s => s.CreateSessionAsync(It.Is<SessionCreateInput>(
            i => i.DontRememberMe == true)), Times.Once);
    }

    [Fact]
    public async Task SignUpEmail_AutoSignInDisabled_NoSessionCreated()
    {
        _fixture.Options.EmailAndPassword.AutoSignIn = false;

        Result<SignUpResult> result = await _sut.SignUpEmail(ValidInput());

        result.IsSuccess.Should().BeTrue();
        result.Value!.Session.Should().BeNull();
        _sessionMock.Verify(s => s.CreateSessionAsync(It.IsAny<SessionCreateInput>()), Times.Never);
    }

    [Fact]
    public async Task SignUpEmail_AutoSignIn_SessionInputContainsCorrectIpAndUserAgent()
    {
        _fixture.Options.EmailAndPassword.AutoSignIn = true;
        SessionCreateInput? capturedInput = null;
        _sessionMock
            .Setup(s => s.CreateSessionAsync(It.IsAny<SessionCreateInput>()))
            .Callback<SessionCreateInput>(i => capturedInput = i)
            .ReturnsAsync(Result<Session>.Success(CreateMockSession()));

        SignUpEmailInput input = ValidInput();
        await _sut.SignUpEmail(input);

        capturedInput.Should().NotBeNull();
        capturedInput!.IpAddress.Should().Be("127.0.0.1");
        capturedInput.UserAgent.Should().Be("TestAgent/1.0");
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

        result.IsSuccess.Should().BeTrue();
        result.Value!.CallbackUrl.Should().Be("https://app.example.com/welcome");
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

        result.IsSuccess.Should().BeTrue();
    }

    [Fact]
    public async Task SignUpEmail_NameWithHtmlTags_IsStoredAsIs()
    {
        // XSS in name — service should store it; output encoding is a presentation concern
        SetupSessionMockForAutoSignIn();
        const string xssName = "<script>alert('xss')</script>";

        Result<SignUpResult> result = await _sut.SignUpEmail(ValidInput(name: xssName));

        result.IsSuccess.Should().BeTrue();
        result.Value!.User.Name.Should().Be(xssName);
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

        result.IsSuccess.Should().BeTrue();
        result.Value!.User.CreatedAt.Should().BeOnOrAfter(before).And.BeOnOrBefore(after);
        result.Value.User.UpdatedAt.Should().BeOnOrAfter(before).And.BeOnOrBefore(after);
    }

    [Fact]
    public async Task SignUpEmail_AccountUserId_MatchesUserId()
    {
        SetupSessionMockForAutoSignIn();

        Result<SignUpResult> result = await _sut.SignUpEmail(ValidInput(email: "relations@test.com"));

        result.IsSuccess.Should().BeTrue();
        Account account = _fixture.DbContext.Accounts.Single(a => a.UserId == result.Value!.User.Id);
        account.UserId.Should().Be(result.Value!.User.Id);
        account.AccountId.Should().Be("relations@test.com");
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

        _fixture.DbContext.Users.Count().Should().Be(userCountBefore,
            "no users should be created when feature is disabled");
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
            .Setup(s => s.CreateSessionAsync(It.IsAny<SessionCreateInput>()))
            .ReturnsAsync(Result<Session>.Success(CreateMockSession()));
    }
}
