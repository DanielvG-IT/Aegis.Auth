using Aegis.Auth.Core.Crypto;
using Aegis.Auth.Entities;
using Aegis.Auth.Features.PasswordReset;
using Aegis.Auth.Tests.Helpers;

namespace Aegis.Auth.Tests.Features;

public sealed class PasswordResetServiceTests : IDisposable
{
    private readonly ServiceTestFixture _fixture;
    private readonly PasswordResetService _sut;

    public PasswordResetServiceTests()
    {
        _fixture = new ServiceTestFixture();
        _sut = new PasswordResetService(_fixture.DbContext);
    }

    public void Dispose() => _fixture.Dispose();

    private User CreateTestUser(string? id = null) => new()
    {
        Id = id ?? Guid.CreateVersion7().ToString(),
        Name = "Password Reset Test User",
        Email = "resettest@test.com",
        CreatedAt = DateTime.UtcNow,
        UpdatedAt = DateTime.UtcNow,
    };

    private Account CreatePasswordAccount(string userId, string? passwordHash = null) => new()
    {
        Id = Guid.CreateVersion7().ToString(),
        UserId = userId,
        ProviderId = "credential",
        AccountId = userId,
        PasswordHash = passwordHash ?? BCrypt.Net.BCrypt.HashPassword("OldPassword123!"),
        CreatedAt = DateTime.UtcNow,
        UpdatedAt = DateTime.UtcNow,
    };

    [Fact]
    public async Task GenerateResetToken_ValidUser_ReturnsToken()
    {
        // Arrange
        var user = CreateTestUser();
        _fixture.DbContext.Users.Add(user);
        await _fixture.DbContext.SaveChangesAsync();

        // Act
        var token = await _sut.GenerateResetTokenAsync(user.Id);

        // Assert
        Assert.NotNull(token);
        Assert.NotEmpty(token);
        Assert.Equal(32, token.Length);
    }

    [Fact]
    public async Task GenerateResetToken_StoresTokenHashNotRaw()
    {
        // Arrange
        var user = CreateTestUser();
        _fixture.DbContext.Users.Add(user);
        await _fixture.DbContext.SaveChangesAsync();

        // Act
        var rawToken = await _sut.GenerateResetTokenAsync(user.Id);

        // Assert
        var authToken = _fixture.DbContext.AuthTokens
            .FirstOrDefault(t => t.UserId == user.Id && t.Purpose == "password-reset");

        Assert.NotNull(authToken);
        Assert.NotEqual(rawToken, authToken.TokenHash);
        Assert.Equal(AegisCrypto.HashToken(rawToken), authToken.TokenHash);
    }

    [Fact]
    public async Task ResetPassword_ValidToken_SucceedsAndUpdatesPassword()
    {
        // Arrange
        var user = CreateTestUser();
        var account = CreatePasswordAccount(user.Id);
        _fixture.DbContext.Users.Add(user);
        _fixture.DbContext.Accounts.Add(account);
        await _fixture.DbContext.SaveChangesAsync();

        var oldHash = account.PasswordHash;
        var rawToken = await _sut.GenerateResetTokenAsync(user.Id);
        var newPasswordHash = BCrypt.Net.BCrypt.HashPassword("NewPassword456!");

        // Act
        var result = await _sut.ResetPasswordAsync(user.Id, rawToken, newPasswordHash);

        // Assert
        Assert.True(result);
        var updatedAccount = _fixture.DbContext.Accounts
            .First(a => a.UserId == user.Id);
        Assert.NotEqual(oldHash, updatedAccount.PasswordHash);
        Assert.Equal(newPasswordHash, updatedAccount.PasswordHash);
    }

    [Fact]
    public async Task ResetPassword_InvalidToken_Fails()
    {
        // Arrange
        var user = CreateTestUser();
        var account = CreatePasswordAccount(user.Id);
        _fixture.DbContext.Users.Add(user);
        _fixture.DbContext.Accounts.Add(account);
        await _fixture.DbContext.SaveChangesAsync();

        var newPasswordHash = BCrypt.Net.BCrypt.HashPassword("NewPassword456!");

        // Act
        var result = await _sut.ResetPasswordAsync(user.Id, "invalid-token", newPasswordHash);

        // Assert
        Assert.False(result);
    }

    [Fact]
    public async Task ResetPassword_ExpiredToken_Fails()
    {
        // Arrange
        var user = CreateTestUser();
        var account = CreatePasswordAccount(user.Id);
        _fixture.DbContext.Users.Add(user);
        _fixture.DbContext.Accounts.Add(account);
        await _fixture.DbContext.SaveChangesAsync();

        var rawToken = await _sut.GenerateResetTokenAsync(user.Id);

        // Expire the token
        var authToken = _fixture.DbContext.AuthTokens
            .First(t => t.UserId == user.Id);
        authToken.ExpiresAt = DateTime.UtcNow.AddMinutes(-1);
        _fixture.DbContext.AuthTokens.Update(authToken);
        await _fixture.DbContext.SaveChangesAsync();

        var newPasswordHash = BCrypt.Net.BCrypt.HashPassword("NewPassword456!");

        // Act
        var result = await _sut.ResetPasswordAsync(user.Id, rawToken, newPasswordHash);

        // Assert
        Assert.False(result);
    }

    [Fact]
    public async Task ResetPassword_AlreadyConsumed_Fails()
    {
        // Arrange
        var user = CreateTestUser();
        var account = CreatePasswordAccount(user.Id);
        _fixture.DbContext.Users.Add(user);
        _fixture.DbContext.Accounts.Add(account);
        await _fixture.DbContext.SaveChangesAsync();

        var rawToken = await _sut.GenerateResetTokenAsync(user.Id);
        var newPasswordHash = BCrypt.Net.BCrypt.HashPassword("NewPassword456!");

        // Use the token once
        await _sut.ResetPasswordAsync(user.Id, rawToken, newPasswordHash);

        // Act — try to use again
        var result = await _sut.ResetPasswordAsync(user.Id, rawToken, newPasswordHash);

        // Assert
        Assert.False(result);
    }

    [Fact]
    public async Task ResetPassword_SingleUseOnly()
    {
        // Arrange
        var user = CreateTestUser();
        var account = CreatePasswordAccount(user.Id);
        _fixture.DbContext.Users.Add(user);
        _fixture.DbContext.Accounts.Add(account);
        await _fixture.DbContext.SaveChangesAsync();

        var rawToken = await _sut.GenerateResetTokenAsync(user.Id);
        var newPasswordHash = BCrypt.Net.BCrypt.HashPassword("NewPassword456!");

        // Act — first reset
        var firstResult = await _sut.ResetPasswordAsync(user.Id, rawToken, newPasswordHash);
        // Second reset attempt with same token
        var secondResult = await _sut.ResetPasswordAsync(user.Id, rawToken, newPasswordHash);

        // Assert
        Assert.True(firstResult);
        Assert.False(secondResult);
    }

    [Fact]
    public async Task ResetPassword_MarkTokenAsConsumed()
    {
        // Arrange
        var user = CreateTestUser();
        var account = CreatePasswordAccount(user.Id);
        _fixture.DbContext.Users.Add(user);
        _fixture.DbContext.Accounts.Add(account);
        await _fixture.DbContext.SaveChangesAsync();

        var rawToken = await _sut.GenerateResetTokenAsync(user.Id);
        var newPasswordHash = BCrypt.Net.BCrypt.HashPassword("NewPassword456!");

        // Act
        await _sut.ResetPasswordAsync(user.Id, rawToken, newPasswordHash);

        // Assert
        var authToken = _fixture.DbContext.AuthTokens
            .First(t => t.UserId == user.Id);
        Assert.NotNull(authToken.ConsumedAt);
    }

    [Fact]
    public async Task ResetPassword_DifferentPurposeToken_Fails()
    {
        // This verifies that a password-reset token won't accidentally accept
        // an email-verification token with the same hash (shouldn't happen, but good to verify).

        // Arrange
        var user = CreateTestUser();
        var account = CreatePasswordAccount(user.Id);
        _fixture.DbContext.Users.Add(user);
        _fixture.DbContext.Accounts.Add(account);
        await _fixture.DbContext.SaveChangesAsync();

        // Create an email-verification token instead
        var rawToken = AegisCrypto.RandomStringGenerator(32, "a-z", "A-Z", "0-9");
        var authToken = new AuthToken
        {
            Id = Guid.CreateVersion7().ToString(),
            TokenHash = AegisCrypto.HashToken(rawToken),
            Purpose = "email-verification", // Different purpose
            ExpiresAt = DateTime.UtcNow.AddMinutes(15),
            CreatedAt = DateTime.UtcNow,
            UserId = user.Id,
        };
        _fixture.DbContext.AuthTokens.Add(authToken);
        await _fixture.DbContext.SaveChangesAsync();

        var newPasswordHash = BCrypt.Net.BCrypt.HashPassword("NewPassword456!");

        // Act
        var result = await _sut.ResetPasswordAsync(user.Id, rawToken, newPasswordHash);

        // Assert
        Assert.False(result);
    }
}
