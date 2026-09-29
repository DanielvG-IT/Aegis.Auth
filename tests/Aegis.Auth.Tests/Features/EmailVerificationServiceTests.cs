using Aegis.Auth.Constants;
using Aegis.Auth.Core.Crypto;
using Aegis.Auth.Entities;
using Aegis.Auth.Features.EmailVerification;
using Aegis.Auth.Options;
using Aegis.Auth.Tests.Helpers;

using Microsoft.Extensions.DependencyInjection;

namespace Aegis.Auth.Tests.Features;

public sealed class EmailVerificationServiceTests : IDisposable
{
    private readonly ServiceTestFixture _fixture;
    private readonly ServiceProvider _services = new ServiceCollection().BuildServiceProvider();
    private readonly List<SendVerificationEmailContext> _sent = [];
    private readonly EmailVerificationService _sut;

    public EmailVerificationServiceTests()
    {
        _fixture = new ServiceTestFixture(o =>
            o.EmailVerification.SendVerificationEmail = (ctx, _) =>
            {
                _sent.Add(ctx);
                return Task.CompletedTask;
            });
        _sut = new EmailVerificationService(
            Microsoft.Extensions.Options.Options.Create(_fixture.Options),
            _fixture.LoggerFactory,
            _fixture.DbContext,
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
    public async Task GenerateVerificationToken_StoresHashWithConfiguredExpiry()
    {
        _fixture.Options.EmailVerification.ExpiresIn = 60;
        var (user, _) = await _fixture.SeedUserAsync();

        var rawToken = await _sut.GenerateVerificationTokenAsync(user.Id);

        Assert.Equal(32, rawToken.Length);
        AuthToken authToken = StoredToken(rawToken)!;
        Assert.NotEqual(rawToken, authToken.TokenHash);
        Assert.Equal(EmailVerificationService.TokenPurpose, authToken.Purpose);
        Assert.InRange(authToken.ExpiresAt - authToken.CreatedAt, TimeSpan.FromSeconds(59), TimeSpan.FromSeconds(61));
    }

    [Fact]
    public async Task GenerateVerificationToken_InvalidatesPreviousUnusedTokens()
    {
        var (user, _) = await _fixture.SeedUserAsync();

        var first = await _sut.GenerateVerificationTokenAsync(user.Id);
        var second = await _sut.GenerateVerificationTokenAsync(user.Id);

        Assert.False((await _sut.VerifyEmailAsync(first)).IsSuccess);
        Assert.True((await _sut.VerifyEmailAsync(second)).IsSuccess);
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // SEND — delivery via the configured delegate
    // ═══════════════════════════════════════════════════════════════════════════

    [Fact]
    public async Task SendVerificationEmail_UnverifiedUser_DeliversRawTokenToDelegate()
    {
        var (user, _) = await _fixture.SeedUserAsync();

        Result result = await _sut.SendVerificationEmailAsync(user);

        Assert.True(result.IsSuccess);
        SendVerificationEmailContext sent = Assert.Single(_sent);
        Assert.Equal(user.Id, sent.User.Id);
        Assert.NotNull(StoredToken(sent.Token));
    }

    [Fact]
    public async Task SendVerificationEmail_AlreadyVerified_ReturnsEmailAlreadyVerified()
    {
        var (user, _) = await _fixture.SeedUserAsync();
        user.EmailVerified = true;

        Result result = await _sut.SendVerificationEmailAsync(user);

        Assert.Equal(AuthErrors.Identity.EmailAlreadyVerified, result.ErrorCode);
        Assert.Empty(_sent);
    }

    [Fact]
    public async Task SendVerificationEmail_NoDelegate_ReturnsNotEnabled()
    {
        _fixture.Options.EmailVerification.SendVerificationEmail = null;
        var (user, _) = await _fixture.SeedUserAsync();

        Result result = await _sut.SendVerificationEmailAsync(user);

        Assert.Equal(AuthErrors.System.VerificationEmailNotEnabled, result.ErrorCode);
        Assert.Empty(_fixture.DbContext.AuthTokens);
    }

    [Fact]
    public async Task SendVerificationEmail_DelegateThrows_ReturnsInternalError()
    {
        _fixture.Options.EmailVerification.SendVerificationEmail = (_, _) => throw new InvalidOperationException("SMTP down");
        var (user, _) = await _fixture.SeedUserAsync();

        Result result = await _sut.SendVerificationEmailAsync(user);

        Assert.Equal(AuthErrors.System.InternalError, result.ErrorCode);
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // REQUEST BY EMAIL — user enumeration
    // ═══════════════════════════════════════════════════════════════════════════

    [Fact]
    public async Task RequestVerificationEmail_UnverifiedUser_SendsWithNormalizedEmail()
    {
        await _fixture.SeedUserAsync(email: "existing@test.com");

        Result result = await _sut.RequestVerificationEmailAsync(" Existing@TEST.com ");

        Assert.True(result.IsSuccess);
        Assert.Single(_sent);
    }

    [Fact]
    public async Task RequestVerificationEmail_UnknownEmail_SucceedsWithoutSending()
    {
        Result result = await _sut.RequestVerificationEmailAsync("nobody@test.com");

        Assert.True(result.IsSuccess);
        Assert.Empty(_sent);
    }

    [Fact]
    public async Task RequestVerificationEmail_AlreadyVerified_SucceedsWithoutSending()
    {
        var (user, _) = await _fixture.SeedUserAsync();
        user.EmailVerified = true;
        await _fixture.DbContext.SaveChangesAsync();

        Result result = await _sut.RequestVerificationEmailAsync(user.Email);

        Assert.True(result.IsSuccess);
        Assert.Empty(_sent);
    }

    [Fact]
    public async Task RequestVerificationEmail_DelegateThrows_StillReportsSuccess()
    {
        _fixture.Options.EmailVerification.SendVerificationEmail = (_, _) => throw new InvalidOperationException("SMTP down");
        var (user, _) = await _fixture.SeedUserAsync();

        Result result = await _sut.RequestVerificationEmailAsync(user.Email);

        Assert.True(result.IsSuccess);
    }

    [Fact]
    public async Task RequestVerificationEmail_BlankEmail_ReturnsEmailRequired()
    {
        Result result = await _sut.RequestVerificationEmailAsync(" ");

        Assert.Equal(AuthErrors.Validation.EmailRequired, result.ErrorCode);
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // VERIFY — token redemption without a session
    // ═══════════════════════════════════════════════════════════════════════════

    [Fact]
    public async Task VerifyEmail_ValidToken_MarksUserVerifiedAndConsumesToken()
    {
        var (user, _) = await _fixture.SeedUserAsync();
        var rawToken = await _sut.GenerateVerificationTokenAsync(user.Id);

        Result<User> result = await _sut.VerifyEmailAsync(rawToken);

        Assert.True(result.IsSuccess);
        Assert.Equal(user.Id, result.Value!.Id);
        Assert.True(user.EmailVerified);
        Assert.NotNull(StoredToken(rawToken)!.ConsumedAt);
    }

    [Fact]
    public async Task VerifyEmail_UnknownToken_ReturnsInvalidToken()
    {
        Result<User> result = await _sut.VerifyEmailAsync("definitely-not-a-real-token-value");

        Assert.Equal(AuthErrors.Token.InvalidToken, result.ErrorCode);
    }

    [Fact]
    public async Task VerifyEmail_ExpiredToken_ReturnsInvalidToken()
    {
        var (user, _) = await _fixture.SeedUserAsync();
        var rawToken = await _sut.GenerateVerificationTokenAsync(user.Id);
        StoredToken(rawToken)!.ExpiresAt = DateTime.UtcNow.AddMinutes(-1);
        await _fixture.DbContext.SaveChangesAsync();

        Result<User> result = await _sut.VerifyEmailAsync(rawToken);

        Assert.Equal(AuthErrors.Token.InvalidToken, result.ErrorCode);
        Assert.False(user.EmailVerified);
    }

    [Fact]
    public async Task VerifyEmail_TokenIsSingleUse()
    {
        var (user, _) = await _fixture.SeedUserAsync();
        var rawToken = await _sut.GenerateVerificationTokenAsync(user.Id);

        Assert.True((await _sut.VerifyEmailAsync(rawToken)).IsSuccess);
        Result<User> second = await _sut.VerifyEmailAsync(rawToken);

        Assert.Equal(AuthErrors.Token.InvalidToken, second.ErrorCode);
    }

    [Fact]
    public async Task VerifyEmail_PasswordResetToken_IsRejected()
    {
        var (user, _) = await _fixture.SeedUserAsync();
        const string rawToken = "reset-token-for-other-purpose";
        _fixture.DbContext.AuthTokens.Add(new AuthToken
        {
            Id = Guid.CreateVersion7().ToString(),
            TokenHash = AegisCrypto.HashToken(rawToken),
            Purpose = "password-reset",
            ExpiresAt = DateTime.UtcNow.AddMinutes(10),
            CreatedAt = DateTime.UtcNow,
            UserId = user.Id,
        });
        await _fixture.DbContext.SaveChangesAsync();

        Result<User> result = await _sut.VerifyEmailAsync(rawToken);

        Assert.Equal(AuthErrors.Token.InvalidToken, result.ErrorCode);
        Assert.False(user.EmailVerified);
    }

    [Fact]
    public async Task VerifyEmail_BlankToken_ReturnsInvalidInput()
    {
        Result<User> result = await _sut.VerifyEmailAsync("");

        Assert.Equal(AuthErrors.Validation.InvalidInput, result.ErrorCode);
    }
}
