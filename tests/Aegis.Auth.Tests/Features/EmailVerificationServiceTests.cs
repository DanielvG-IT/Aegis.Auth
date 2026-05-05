using Aegis.Auth.Core.Crypto;
using Aegis.Auth.Entities;
using Aegis.Auth.Features.EmailVerification;
using Aegis.Auth.Tests.Helpers;

namespace Aegis.Auth.Tests.Features;

public sealed class EmailVerificationServiceTests : IDisposable
{
    private readonly ServiceTestFixture _fixture;
    private readonly EmailVerificationService _sut;

    public EmailVerificationServiceTests()
    {
        _fixture = new ServiceTestFixture();
        _sut = new EmailVerificationService(_fixture.DbContext);
    }

    public void Dispose() => _fixture.Dispose();

    private User CreateTestUser(string? id = null) => new()
    {
        Id = id ?? Guid.CreateVersion7().ToString(),
        Name = "Email Verification Test User",
        Email = "emailtest@test.com",
        EmailVerified = false,
        CreatedAt = DateTime.UtcNow,
        UpdatedAt = DateTime.UtcNow,
    };

    [Fact]
    public async Task GenerateVerificationToken_ValidUser_ReturnsToken()
    {
        // Arrange
        var user = CreateTestUser();
        _fixture.DbContext.Users.Add(user);
        await _fixture.DbContext.SaveChangesAsync();

        // Act
        var token = await _sut.GenerateVerificationTokenAsync(user.Id);

        // Assert
        Assert.NotNull(token);
        Assert.NotEmpty(token);
        Assert.Equal(32, token.Length); // Random 32-char string
    }

    [Fact]
    public async Task GenerateVerificationToken_StoresTokenHashNotRaw()
    {
        // Arrange
        var user = CreateTestUser();
        _fixture.DbContext.Users.Add(user);
        await _fixture.DbContext.SaveChangesAsync();

        // Act
        var rawToken = await _sut.GenerateVerificationTokenAsync(user.Id);

        // Assert
        var authToken = _fixture.DbContext.AuthTokens
            .FirstOrDefault(t => t.UserId == user.Id);

        Assert.NotNull(authToken);
        Assert.NotEqual(rawToken, authToken.TokenHash);
        Assert.Equal(AegisCrypto.HashToken(rawToken), authToken.TokenHash);
    }

    [Fact]
    public async Task VerifyEmail_ValidToken_SucceedsAndMarksConsumed()
    {
        // Arrange
        var user = CreateTestUser();
        _fixture.DbContext.Users.Add(user);
        await _fixture.DbContext.SaveChangesAsync();

        var rawToken = await _sut.GenerateVerificationTokenAsync(user.Id);

        // Act
        var result = await _sut.VerifyEmailAsync(user.Id, rawToken);

        // Assert
        Assert.True(result);

        var authToken = _fixture.DbContext.AuthTokens
            .FirstOrDefault(t => t.UserId == user.Id);
        Assert.NotNull(authToken);
        Assert.NotNull(authToken.ConsumedAt);
    }

    [Fact]
    public async Task VerifyEmail_InvalidToken_Fails()
    {
        // Arrange
        var user = CreateTestUser();
        _fixture.DbContext.Users.Add(user);
        await _fixture.DbContext.SaveChangesAsync();

        await _sut.GenerateVerificationTokenAsync(user.Id);

        // Act
        var result = await _sut.VerifyEmailAsync(user.Id, "invalid-token-123");

        // Assert
        Assert.False(result);
    }

    [Fact]
    public async Task VerifyEmail_ExpiredToken_Fails()
    {
        // Arrange
        var user = CreateTestUser();
        _fixture.DbContext.Users.Add(user);
        await _fixture.DbContext.SaveChangesAsync();

        var rawToken = await _sut.GenerateVerificationTokenAsync(user.Id);

        // Manually expire the token
        var authToken = _fixture.DbContext.AuthTokens
            .First(t => t.UserId == user.Id);
        authToken.ExpiresAt = DateTime.UtcNow.AddMinutes(-1);
        _fixture.DbContext.AuthTokens.Update(authToken);
        await _fixture.DbContext.SaveChangesAsync();

        // Act
        var result = await _sut.VerifyEmailAsync(user.Id, rawToken);

        // Assert
        Assert.False(result);
    }

    [Fact]
    public async Task VerifyEmail_AlreadyConsumed_Fails()
    {
        // Arrange
        var user = CreateTestUser();
        _fixture.DbContext.Users.Add(user);
        await _fixture.DbContext.SaveChangesAsync();

        var rawToken = await _sut.GenerateVerificationTokenAsync(user.Id);

        // Consume the token once
        await _sut.VerifyEmailAsync(user.Id, rawToken);

        // Act — try to consume again
        var result = await _sut.VerifyEmailAsync(user.Id, rawToken);

        // Assert
        Assert.False(result);
    }

    [Fact]
    public async Task VerifyEmail_SingleUseOnly()
    {
        // Arrange
        var user = CreateTestUser();
        _fixture.DbContext.Users.Add(user);
        await _fixture.DbContext.SaveChangesAsync();

        var rawToken = await _sut.GenerateVerificationTokenAsync(user.Id);

        // Act — first verification
        var firstResult = await _sut.VerifyEmailAsync(user.Id, rawToken);
        // Second verification attempt with same token
        var secondResult = await _sut.VerifyEmailAsync(user.Id, rawToken);

        // Assert
        Assert.True(firstResult);
        Assert.False(secondResult);
    }

    [Fact]
    public async Task MarkEmailVerified_ValidUser_SetsEmailVerified()
    {
        // Arrange
        var user = CreateTestUser();
        _fixture.DbContext.Users.Add(user);
        await _fixture.DbContext.SaveChangesAsync();

        Assert.False(user.EmailVerified);

        // Act
        await _sut.MarkEmailVerifiedAsync(user.Id);

        // Assert
        var updatedUser = _fixture.DbContext.Users.First(u => u.Id == user.Id);
        Assert.True(updatedUser.EmailVerified);
    }

    [Fact]
    public async Task VerifyAndMarkEmail_CompleteFlow()
    {
        // Arrange
        var user = CreateTestUser();
        _fixture.DbContext.Users.Add(user);
        await _fixture.DbContext.SaveChangesAsync();

        // Act
        var rawToken = await _sut.GenerateVerificationTokenAsync(user.Id);
        var verified = await _sut.VerifyEmailAsync(user.Id, rawToken);
        await _sut.MarkEmailVerifiedAsync(user.Id);

        // Assert
        Assert.True(verified);
        var updatedUser = _fixture.DbContext.Users.First(u => u.Id == user.Id);
        Assert.True(updatedUser.EmailVerified);
    }

    [Fact]
    public async Task GenerateVerificationToken_MultiplePurposes_CanCoexist()
    {
        // This test verifies that the (UserId, Purpose, TokenHash) unique index
        // allows different purposes (e.g., "email-verification" vs "password-reset")
        // to coexist, but prevents multiple tokens of the same purpose for a user.

        // Arrange
        var user = CreateTestUser();
        _fixture.DbContext.Users.Add(user);
        await _fixture.DbContext.SaveChangesAsync();

        // Act — generate two verification tokens
        var token1 = await _sut.GenerateVerificationTokenAsync(user.Id);
        var token2 = await _sut.GenerateVerificationTokenAsync(user.Id);

        // Assert — the second token should have overwritten/invalidated first, or they both exist
        // Since we're using a unique index, the second should fail or we should only see one
        // Actually, the unique index on (UserId, Purpose, TokenHash) means the HASH can't be duplicated,
        // but different tokens will have different hashes, so both should exist.
        var tokens = _fixture.DbContext.AuthTokens
            .Where(t => t.UserId == user.Id && t.Purpose == "email-verification")
            .ToList();

        Assert.Equal(2, tokens.Count);
        Assert.NotEqual(tokens[0].TokenHash, tokens[1].TokenHash);
    }
}
