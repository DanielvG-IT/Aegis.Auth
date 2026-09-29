using Aegis.Auth.Constants;
using Aegis.Auth.Core.Crypto;
using Aegis.Auth.Entities;
using Aegis.Auth.Features.PasswordReset;
using Aegis.Auth.Features.Sessions;
using Aegis.Auth.Options;
using Aegis.Auth.Tests.Helpers;

using Microsoft.Extensions.DependencyInjection;

using Moq;

namespace Aegis.Auth.Tests.Features;

public sealed class PasswordResetServiceTests : IDisposable
{
    private readonly ServiceTestFixture _fixture;
    private readonly ServiceProvider _services = new ServiceCollection().BuildServiceProvider();
    private readonly Mock<ISessionService> _sessionMock;
    private readonly List<SendResetPasswordContext> _sent = [];
    private readonly PasswordResetService _sut;

    public PasswordResetServiceTests()
    {
        _fixture = new ServiceTestFixture(o =>
            o.EmailAndPassword.SendResetPassword = (ctx, _) =>
            {
                _sent.Add(ctx);
                return Task.CompletedTask;
            });
        _sessionMock = new Mock<ISessionService>(MockBehavior.Strict);
        _sessionMock
            .Setup(s => s.RevokeAllSessionsAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(Result.Success());
        _sut = new PasswordResetService(
            Microsoft.Extensions.Options.Options.Create(_fixture.Options),
            _fixture.LoggerFactory,
            _fixture.DbContext,
            _sessionMock.Object,
            _services);
    }

    public void Dispose()
    {
        _services.Dispose();
        _fixture.Dispose();
    }

    private AuthToken? StoredToken(string rawToken) =>
        _fixture.DbContext.AuthTokens.FirstOrDefault(t => t.TokenHash == AegisCrypto.HashToken(rawToken));

    // ═══════════════════════════════════════════════════════════════════════════
    // TOKEN GENERATION
    // ═══════════════════════════════════════════════════════════════════════════

    [Fact]
    public async Task GenerateResetToken_ValidUser_Returns32CharToken()
    {
        var (user, _) = await _fixture.SeedUserAsync();

        var token = await _sut.GenerateResetTokenAsync(user.Id);

        Assert.Equal(32, token.Length);
    }

    [Fact]
    public async Task GenerateResetToken_StoresTokenHashNotRaw()
    {
        var (user, _) = await _fixture.SeedUserAsync();

        var rawToken = await _sut.GenerateResetTokenAsync(user.Id);

        AuthToken? authToken = _fixture.DbContext.AuthTokens.Single(t => t.UserId == user.Id);
        Assert.NotEqual(rawToken, authToken.TokenHash);
        Assert.Equal(AegisCrypto.HashToken(rawToken), authToken.TokenHash);
        Assert.Equal(PasswordResetService.TokenPurpose, authToken.Purpose);
    }

    [Fact]
    public async Task GenerateResetToken_UsesConfiguredExpiry()
    {
        _fixture.Options.EmailAndPassword.ResetPasswordTokenExpiresIn = 120;
        var (user, _) = await _fixture.SeedUserAsync();

        var rawToken = await _sut.GenerateResetTokenAsync(user.Id);

        AuthToken authToken = StoredToken(rawToken)!;
        Assert.InRange(authToken.ExpiresAt - authToken.CreatedAt, TimeSpan.FromSeconds(119), TimeSpan.FromSeconds(121));
    }

    [Fact]
    public async Task GenerateResetToken_InvalidatesPreviousUnusedTokens()
    {
        var (user, _) = await _fixture.SeedUserAsync();

        var first = await _sut.GenerateResetTokenAsync(user.Id);
        var second = await _sut.GenerateResetTokenAsync(user.Id);

        Assert.False((await _sut.ResetPasswordAsync(first, "NewPassword123!")).IsSuccess);
        Assert.True((await _sut.ResetPasswordAsync(second, "NewPassword123!")).IsSuccess);
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // REQUEST RESET — delivery and user enumeration
    // ═══════════════════════════════════════════════════════════════════════════

    [Fact]
    public async Task RequestPasswordReset_ExistingUser_DeliversRawTokenToDelegate()
    {
        var (user, _) = await _fixture.SeedUserAsync();

        Result result = await _sut.RequestPasswordResetAsync(user.Email);

        Assert.True(result.IsSuccess);
        SendResetPasswordContext sent = Assert.Single(_sent);
        Assert.Equal(user.Id, sent.User.Id);
        Assert.NotNull(StoredToken(sent.Token));
    }

    [Fact]
    public async Task RequestPasswordReset_NormalizesEmail()
    {
        await _fixture.SeedUserAsync(email: "existing@test.com");

        Result result = await _sut.RequestPasswordResetAsync("  EXISTING@Test.com ");

        Assert.True(result.IsSuccess);
        Assert.Single(_sent);
    }

    [Fact]
    public async Task RequestPasswordReset_UnknownEmail_SucceedsWithoutSendingOrStoringToken()
    {
        Result result = await _sut.RequestPasswordResetAsync("nobody@test.com");

        Assert.True(result.IsSuccess);
        Assert.Empty(_sent);
        Assert.Empty(_fixture.DbContext.AuthTokens);
    }

    [Fact]
    public async Task RequestPasswordReset_OAuthOnlyUser_SucceedsWithoutSending()
    {
        User user = await _fixture.SeedOAuthOnlyUserAsync();

        Result result = await _sut.RequestPasswordResetAsync(user.Email);

        Assert.True(result.IsSuccess);
        Assert.Empty(_sent);
    }

    [Fact]
    public async Task RequestPasswordReset_DelegateThrows_StillReportsSuccess()
    {
        _fixture.Options.EmailAndPassword.SendResetPassword = (_, _) => throw new InvalidOperationException("SMTP down");
        var (user, _) = await _fixture.SeedUserAsync();

        Result result = await _sut.RequestPasswordResetAsync(user.Email);

        Assert.True(result.IsSuccess);
    }

    [Fact]
    public async Task RequestPasswordReset_NoDelegateConfigured_ReturnsFeatureDisabled()
    {
        _fixture.Options.EmailAndPassword.SendResetPassword = null;
        var (user, _) = await _fixture.SeedUserAsync();

        Result result = await _sut.RequestPasswordResetAsync(user.Email);

        Assert.False(result.IsSuccess);
        Assert.Equal(AuthErrors.System.FeatureDisabled, result.ErrorCode);
        Assert.Empty(_fixture.DbContext.AuthTokens);
    }

    [Fact]
    public async Task RequestPasswordReset_EmailPasswordDisabled_ReturnsFeatureDisabled()
    {
        _fixture.Options.EmailAndPassword.Enabled = false;

        Result result = await _sut.RequestPasswordResetAsync("existing@test.com");

        Assert.Equal(AuthErrors.System.FeatureDisabled, result.ErrorCode);
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    public async Task RequestPasswordReset_BlankEmail_ReturnsEmailRequired(string email)
    {
        Result result = await _sut.RequestPasswordResetAsync(email);

        Assert.Equal(AuthErrors.Validation.EmailRequired, result.ErrorCode);
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // RESET — token redemption without a session
    // ═══════════════════════════════════════════════════════════════════════════

    [Fact]
    public async Task ResetPassword_ValidToken_UpdatesPasswordAndConsumesToken()
    {
        var (user, account) = await _fixture.SeedUserAsync();
        var rawToken = await _sut.GenerateResetTokenAsync(user.Id);

        Result result = await _sut.ResetPasswordAsync(rawToken, "NewPassword123!");

        Assert.True(result.IsSuccess);
        Assert.Equal("hashed:NewPassword123!", account.PasswordHash);
        Assert.NotNull(StoredToken(rawToken)!.ConsumedAt);
    }

    [Fact]
    public async Task ResetPassword_RevokesAllSessionsByDefault()
    {
        var (user, _) = await _fixture.SeedUserAsync();
        var rawToken = await _sut.GenerateResetTokenAsync(user.Id);

        await _sut.ResetPasswordAsync(rawToken, "NewPassword123!");

        _sessionMock.Verify(s => s.RevokeAllSessionsAsync(user.Id, It.IsAny<CancellationToken>()), Times.Once);
    }

    [Fact]
    public async Task ResetPassword_RevokeSessionsDisabled_KeepsSessions()
    {
        _fixture.Options.EmailAndPassword.RevokeSessionsOnPasswordReset = false;
        var (user, _) = await _fixture.SeedUserAsync();
        var rawToken = await _sut.GenerateResetTokenAsync(user.Id);

        await _sut.ResetPasswordAsync(rawToken, "NewPassword123!");

        _sessionMock.Verify(s => s.RevokeAllSessionsAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()), Times.Never);
    }

    [Fact]
    public async Task ResetPassword_UnknownToken_ReturnsInvalidToken()
    {
        await _fixture.SeedUserAsync();

        Result result = await _sut.ResetPasswordAsync("definitely-not-a-real-token-value", "NewPassword123!");

        Assert.Equal(AuthErrors.Token.InvalidToken, result.ErrorCode);
    }

    [Fact]
    public async Task ResetPassword_ExpiredToken_ReturnsInvalidToken()
    {
        var (user, account) = await _fixture.SeedUserAsync();
        var rawToken = await _sut.GenerateResetTokenAsync(user.Id);
        StoredToken(rawToken)!.ExpiresAt = DateTime.UtcNow.AddMinutes(-1);
        await _fixture.DbContext.SaveChangesAsync();

        Result result = await _sut.ResetPasswordAsync(rawToken, "NewPassword123!");

        Assert.Equal(AuthErrors.Token.InvalidToken, result.ErrorCode);
        Assert.NotEqual("hashed:NewPassword123!", account.PasswordHash);
    }

    [Fact]
    public async Task ResetPassword_TokenIsSingleUse()
    {
        var (user, account) = await _fixture.SeedUserAsync();
        var rawToken = await _sut.GenerateResetTokenAsync(user.Id);

        Assert.True((await _sut.ResetPasswordAsync(rawToken, "FirstNewPass123!")).IsSuccess);
        Result second = await _sut.ResetPasswordAsync(rawToken, "SecondNewPass123!");

        Assert.Equal(AuthErrors.Token.InvalidToken, second.ErrorCode);
        Assert.Equal("hashed:FirstNewPass123!", account.PasswordHash);
    }

    [Fact]
    public async Task ResetPassword_EmailVerificationToken_IsRejected()
    {
        var (user, _) = await _fixture.SeedUserAsync();
        const string rawToken = "verification-token-for-other-purpose";
        _fixture.DbContext.AuthTokens.Add(new AuthToken
        {
            Id = Guid.CreateVersion7().ToString(),
            TokenHash = AegisCrypto.HashToken(rawToken),
            Purpose = "email-verification",
            ExpiresAt = DateTime.UtcNow.AddMinutes(10),
            CreatedAt = DateTime.UtcNow,
            UserId = user.Id,
        });
        await _fixture.DbContext.SaveChangesAsync();

        Result result = await _sut.ResetPasswordAsync(rawToken, "NewPassword123!");

        Assert.Equal(AuthErrors.Token.InvalidToken, result.ErrorCode);
    }

    [Fact]
    public async Task ResetPassword_UserWithoutCredentialAccount_ReturnsInvalidToken()
    {
        User user = await _fixture.SeedOAuthOnlyUserAsync();
        var rawToken = await _sut.GenerateResetTokenAsync(user.Id);

        Result result = await _sut.ResetPasswordAsync(rawToken, "NewPassword123!");

        Assert.Equal(AuthErrors.Token.InvalidToken, result.ErrorCode);
    }

    [Fact]
    public async Task ResetPassword_TooShortPassword_FailsWithoutConsumingToken()
    {
        var (user, _) = await _fixture.SeedUserAsync();
        var rawToken = await _sut.GenerateResetTokenAsync(user.Id);

        Result result = await _sut.ResetPasswordAsync(rawToken, "short");

        Assert.Equal(AuthErrors.Validation.PasswordTooShort, result.ErrorCode);
        Assert.Null(StoredToken(rawToken)!.ConsumedAt);
    }

    [Fact]
    public async Task ResetPassword_TooLongPassword_Fails()
    {
        var (user, _) = await _fixture.SeedUserAsync();
        var rawToken = await _sut.GenerateResetTokenAsync(user.Id);

        Result result = await _sut.ResetPasswordAsync(rawToken, new string('a', 129));

        Assert.Equal(AuthErrors.Validation.PasswordTooLong, result.ErrorCode);
    }

    [Fact]
    public async Task ResetPassword_CustomValidatorRejects_Fails()
    {
        _fixture.Options.EmailAndPassword.Password.Validate = _ => Task.FromResult(PasswordValidationResult.Invalid("Needs a symbol."));
        var (user, _) = await _fixture.SeedUserAsync();
        var rawToken = await _sut.GenerateResetTokenAsync(user.Id);

        Result result = await _sut.ResetPasswordAsync(rawToken, "NoSymbolsHere1");

        Assert.Equal(AuthErrors.Validation.InvalidInput, result.ErrorCode);
        Assert.Equal("Needs a symbol.", result.Message);
    }

    [Theory]
    [InlineData("")]
    [InlineData("  ")]
    public async Task ResetPassword_BlankToken_ReturnsInvalidInput(string token)
    {
        Result result = await _sut.ResetPasswordAsync(token, "NewPassword123!");

        Assert.Equal(AuthErrors.Validation.InvalidInput, result.ErrorCode);
    }
}
