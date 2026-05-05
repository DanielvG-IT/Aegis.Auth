using Aegis.Auth.Features.OAuth;
using Aegis.Auth.Tests.Helpers;

using Microsoft.AspNetCore.DataProtection;

namespace Aegis.Auth.Tests.Features;

public sealed class TokenEncryptionServiceTests
{
    private readonly IDataProtectionProvider _dataProtectionProvider;
    private readonly TokenEncryptionService _sut;

    public TokenEncryptionServiceTests()
    {
        // Create a test-safe data protection provider
        _dataProtectionProvider = DataProtectionProvider.Create("Aegis.Auth.Tests");
        _sut = new TokenEncryptionService(_dataProtectionProvider);
    }

    [Fact]
    public void EncryptToken_ValidToken_ReturnsEncryptedString()
    {
        // Arrange
        var plaintext = "test-access-token-abc123";

        // Act
        var encrypted = _sut.EncryptToken(plaintext);

        // Assert
        Assert.NotNull(encrypted);
        Assert.NotEmpty(encrypted);
        Assert.NotEqual(plaintext, encrypted);
    }

    [Fact]
    public void DecryptToken_EncryptedToken_ReturnsPlaintext()
    {
        // Arrange
        var plaintext = "test-access-token-abc123";
        var encrypted = _sut.EncryptToken(plaintext);

        // Act
        var decrypted = _sut.DecryptToken(encrypted);

        // Assert
        Assert.NotNull(decrypted);
        Assert.Equal(plaintext, decrypted);
    }

    [Fact]
    public void RoundTrip_Encryption_PreservesValue()
    {
        // Arrange
        var originalToken = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U";

        // Act
        var encrypted = _sut.EncryptToken(originalToken);
        var decrypted = _sut.DecryptToken(encrypted);

        // Assert
        Assert.Equal(originalToken, decrypted);
    }

    [Fact]
    public void EncryptToken_NullValue_ReturnsEmpty()
    {
        // Act
        var result = _sut.EncryptToken(null);

        // Assert
        Assert.Equal(string.Empty, result);
    }

    [Fact]
    public void EncryptToken_EmptyString_ReturnsEmpty()
    {
        // Act
        var result = _sut.EncryptToken(string.Empty);

        // Assert
        Assert.Equal(string.Empty, result);
    }

    [Fact]
    public void DecryptToken_NullValue_ReturnsNull()
    {
        // Act
        var result = _sut.DecryptToken(null);

        // Assert
        Assert.Null(result);
    }

    [Fact]
    public void DecryptToken_EmptyString_ReturnsNull()
    {
        // Act
        var result = _sut.DecryptToken(string.Empty);

        // Assert
        Assert.Null(result);
    }

    [Fact]
    public void DecryptToken_InvalidCiphertext_ReturnsNull()
    {
        // Arrange
        var invalidCiphertext = "this-is-not-valid-encrypted-data";

        // Act
        var result = _sut.DecryptToken(invalidCiphertext);

        // Assert
        Assert.Null(result);
    }

    [Fact]
    public void EncryptToken_LongToken_Succeeds()
    {
        // Arrange
        var longToken = string.Concat(Enumerable.Repeat("a", 2000));

        // Act
        var encrypted = _sut.EncryptToken(longToken);
        var decrypted = _sut.DecryptToken(encrypted);

        // Assert
        Assert.Equal(longToken, decrypted);
    }

    [Fact]
    public void EncryptToken_SpecialCharacters_PreservesDuringRoundTrip()
    {
        // Arrange
        var tokenWithSpecialChars = "token!@#$%^&*()_+-=[]{}|;:',.<>?/~`";

        // Act
        var encrypted = _sut.EncryptToken(tokenWithSpecialChars);
        var decrypted = _sut.DecryptToken(encrypted);

        // Assert
        Assert.Equal(tokenWithSpecialChars, decrypted);
    }
}
