using Aegis.Auth.Constants;
using Aegis.Auth.Entities;
using Aegis.Auth.Features.OAuth;
using Aegis.Auth.Features.Sessions;
using Aegis.Auth.Tests.Helpers;

using Moq;

namespace Aegis.Auth.Tests.Features;

public sealed class OAuthServiceTests : IDisposable
{
    private readonly ServiceTestFixture _fixture;
    private readonly Mock<ISessionService> _sessionMock;
    private readonly OAuthService _sut;

    public OAuthServiceTests()
    {
        _fixture = new ServiceTestFixture(options =>
        {
            options.OAuth.Enabled = true;
            options.OAuth.Google.Enabled = true;
            options.OAuth.Google.ClientId = "client-id";
            options.OAuth.Google.ClientSecret = "client-secret";
        });
        _sessionMock = new Mock<ISessionService>(MockBehavior.Strict);
        _sut = new OAuthService(
            Microsoft.Extensions.Options.Options.Create(_fixture.Options),
            _fixture.DbContext,
            _sessionMock.Object);
    }

    public void Dispose() => _fixture.Dispose();

    [Fact]
    public async Task SignInExternalAsync_WhenOAuthDisabled_ReturnsFeatureDisabled()
    {
        _fixture.Options.OAuth.Enabled = false;

        Result<OAuthSignInResult> result = await _sut.SignInExternalAsync(ValidInput());

        Assert.False(result.IsSuccess);
        Assert.Equal(AuthErrors.System.FeatureDisabled, result.ErrorCode);
    }

    [Fact]
    public async Task SignInExternalAsync_WhenAccountExists_CreatesSessionAndUpdatesTokens()
    {
        var user = await _fixture.SeedOAuthOnlyUserAsync("oauth-existing@test.com");
        var account = _fixture.DbContext.Accounts.Single(a => a.UserId == user.Id && a.ProviderId == "google");
        account.AccountId = "google-sub-1";
        await _fixture.DbContext.SaveChangesAsync();

        SetupSessionMock(user);

        Result<OAuthSignInResult> result = await _sut.SignInExternalAsync(ValidInput(providerAccountId: "google-sub-1"));

        Assert.True(result.IsSuccess);
        Assert.Equal("new-access-token", account.AccessToken);
        Assert.False(result.Value!.CreatedUser);
    }

    [Fact]
    public async Task SignInExternalAsync_WhenNoAccount_CreatesUserAndAccount()
    {
        SetupSessionMock(userId: null);

        Result<OAuthSignInResult> result = await _sut.SignInExternalAsync(ValidInput(email: "new-google@test.com"));

        Assert.True(result.IsSuccess);
        Assert.True(result.Value!.CreatedUser);
        Assert.Equal("new-google@test.com", result.Value.User.Email);
        Assert.Equal("google", result.Value.Account.ProviderId);
    }

    [Fact]
    public async Task SignInExternalAsync_WhenAutoLinkByEmailEnabled_LinksExistingUser()
    {
        _fixture.Options.OAuth.AutoLinkByEmail = true;
        (User user, _) = await _fixture.SeedUserAsync(email: "linkme@test.com");
        SetupSessionMock(user);

        Result<OAuthSignInResult> result = await _sut.SignInExternalAsync(ValidInput(email: "linkme@test.com", providerAccountId: "google-link"));

        Assert.True(result.IsSuccess);
        Assert.True(result.Value!.LinkedByEmail);
        Assert.Equal(user.Id, result.Value.User.Id);
        Assert.Contains(_fixture.DbContext.Accounts, a => a.UserId == user.Id && a.ProviderId == "google" && a.AccountId == "google-link");
    }

    [Fact]
    public async Task SignInExternalAsync_WhenAutoCreateDisabledAndNoLinkedAccount_ReturnsInvalidInput()
    {
        _fixture.Options.OAuth.AutoCreateUser = false;

        Result<OAuthSignInResult> result = await _sut.SignInExternalAsync(ValidInput(email: "missing@test.com"));

        Assert.False(result.IsSuccess);
        Assert.Equal(AuthErrors.Validation.InvalidInput, result.ErrorCode);
    }

    private OAuthSignInInput ValidInput(string providerAccountId = "google-sub-123", string email = "oauth@test.com") =>
        new()
        {
            Identity = new ExternalIdentity
            {
                ProviderId = "google",
                ProviderAccountId = providerAccountId,
                Email = email,
                EmailVerified = true,
                Name = "OAuth User",
                Image = "https://example.com/avatar.png",
                AccessToken = "new-access-token",
                RefreshToken = "refresh-token",
                IdToken = "id-token",
                Scope = "openid profile email",
                AccessTokenExpiresAt = DateTime.UtcNow.AddHours(1),
            },
            IpAddress = "127.0.0.1",
            UserAgent = "TestAgent/1.0",
            RememberMe = true,
        };

    private void SetupSessionMock(User? user = null, string? userId = "generated-user-id")
    {
        _sessionMock
            .Setup(s => s.CreateSessionAsync(It.IsAny<SessionCreateInput>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync((SessionCreateInput input, CancellationToken _) =>
            {
                var resolvedUserId = user?.Id ?? input.User.Id ?? userId!;
                return new Session
                {
                    Id = Guid.CreateVersion7().ToString(),
                    UserId = resolvedUserId,
                    Token = "session-token",
                    ExpiresAt = DateTime.UtcNow.AddHours(1),
                    CreatedAt = DateTime.UtcNow,
                    UpdatedAt = DateTime.UtcNow,
                };
            });
    }
}
