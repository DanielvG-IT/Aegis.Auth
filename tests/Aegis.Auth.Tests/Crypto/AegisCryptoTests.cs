using System.Security.Cryptography;
using System.Text;

using Aegis.Auth.Core.Crypto;


namespace Aegis.Auth.Tests.Crypto;

/// <summary>
/// Adversarial test suite for AegisCrypto.
/// Focus: cryptographic correctness, tamper detection, key derivation invariants,
/// boundary conditions for RandomStringGenerator, Base64Url roundtrips.
/// </summary>
public sealed class AegisCryptoTests
{
    private const string TestSecret = "test-secret-that-is-long-enough-for-hmac-256-operations!!";
    private const string AltSecret = "different-secret-that-is-long-enough-for-hmac-256-ops!!";

    // ═══════════════════════════════════════════════════════════════════════════
    // ENCRYPT / DECRYPT — Roundtrip
    // ═══════════════════════════════════════════════════════════════════════════

    [Fact]
    public void EncryptDecrypt_Roundtrip_ReturnsOriginalText()
    {
        var plaintext = "Hello, Aegis!";

        var encrypted = AegisCrypto.Encrypt(plaintext, TestSecret);
        var decrypted = AegisCrypto.Decrypt(encrypted, TestSecret);

        Assert.Equal(plaintext, decrypted);
    }

    [Fact]
    public void EncryptDecrypt_EmptyString_Roundtrips()
    {
        var encrypted = AegisCrypto.Encrypt("", TestSecret);
        var decrypted = AegisCrypto.Decrypt(encrypted, TestSecret);

        Assert.Equal("", decrypted);
    }

    [Fact]
    public void EncryptDecrypt_UnicodePayload_Roundtrips()
    {
        var unicode = "Pässwörd🔐密码тест";

        var encrypted = AegisCrypto.Encrypt(unicode, TestSecret);
        var decrypted = AegisCrypto.Decrypt(encrypted, TestSecret);

        Assert.Equal(unicode, decrypted);
    }

    [Fact]
    public void EncryptDecrypt_LargePayload_Roundtrips()
    {
        // 1MB payload
        var large = new string('X', 1024 * 1024);

        var encrypted = AegisCrypto.Encrypt(large, TestSecret);
        var decrypted = AegisCrypto.Decrypt(encrypted, TestSecret);

        Assert.Equal(large, decrypted);
    }

    [Fact]
    public void EncryptDecrypt_JsonPayload_Roundtrips()
    {
        var json = """{"userId":"123","roles":["admin","user"],"exp":1700000000}""";

        var encrypted = AegisCrypto.Encrypt(json, TestSecret);
        var decrypted = AegisCrypto.Decrypt(encrypted, TestSecret);

        Assert.Equal(json, decrypted);
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // NONCE UNIQUENESS — Same plaintext must produce different ciphertext
    // ═══════════════════════════════════════════════════════════════════════════

    [Fact]
    public void Encrypt_SamePlaintext_ProducesDifferentCiphertext()
    {
        var plaintext = "deterministic-test";

        var encrypted1 = AegisCrypto.Encrypt(plaintext, TestSecret);
        var encrypted2 = AegisCrypto.Encrypt(plaintext, TestSecret);

        Assert.NotEqual(encrypted2, encrypted1);
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // WRONG KEY — Decrypt with different secret
    // ═══════════════════════════════════════════════════════════════════════════

    [Fact]
    public void Decrypt_WrongKey_ReturnsNull()
    {
        var encrypted = AegisCrypto.Encrypt("secret data", TestSecret);

        var decrypted = AegisCrypto.Decrypt(encrypted, AltSecret);

        Assert.Null(decrypted);
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // TAMPER DETECTION — Modified ciphertext
    // ═══════════════════════════════════════════════════════════════════════════

    [Fact]
    public void Decrypt_TamperedCiphertext_ReturnsNull()
    {
        var encrypted = AegisCrypto.Encrypt("tamper me", TestSecret);

        // Flip a character in the middle of the base64url string
        var chars = encrypted.ToCharArray();
        var mid = chars.Length / 2;
        chars[mid] = chars[mid] == 'A' ? 'B' : 'A';
        var tampered = new string(chars);

        var decrypted = AegisCrypto.Decrypt(tampered, TestSecret);

        Assert.Null(decrypted);
    }

    [Fact]
    public void Decrypt_TruncatedCiphertext_ReturnsNull()
    {
        var encrypted = AegisCrypto.Encrypt("truncate me", TestSecret);

        // Remove last 10 characters (corrupts the auth tag)
        var truncated = encrypted[..^10];

        var decrypted = AegisCrypto.Decrypt(truncated, TestSecret);

        Assert.Null(decrypted);
    }

    [Fact]
    public void Decrypt_AppendedData_ReturnsNull()
    {
        var encrypted = AegisCrypto.Encrypt("extend me", TestSecret);

        var extended = encrypted + "AAAA";

        var decrypted = AegisCrypto.Decrypt(extended, TestSecret);

        Assert.Null(decrypted);
    }

    [Fact]
    public void Decrypt_CompletelyRandomData_ReturnsNull()
    {
        var randomBytes = RandomNumberGenerator.GetBytes(64);
        var randomBase64 = Convert.ToBase64String(randomBytes)
            .Replace("+", "-").Replace("/", "_").TrimEnd('=');

        var decrypted = AegisCrypto.Decrypt(randomBase64, TestSecret);

        Assert.Null(decrypted);
    }

    [Fact]
    public void Decrypt_EmptyString_ReturnsNull()
    {
        var decrypted = AegisCrypto.Decrypt("", TestSecret);

        Assert.Null(decrypted);
    }

    [Fact]
    public void Decrypt_TooShortForNonceAndTag_ReturnsNull()
    {
        // Minimum valid: 12 (nonce) + 16 (tag) = 28 bytes
        // Encode 27 bytes
        var tooShort = AegisCrypto.ToBase64Url(RandomNumberGenerator.GetBytes(27));

        var decrypted = AegisCrypto.Decrypt(tooShort, TestSecret);

        Assert.Null(decrypted);
    }

    [Fact]
    public void Decrypt_ExactlyNonceAndTag_DecryptsAsEmptyString()
    {
        // 28 bytes = 12 nonce + 0 ciphertext + 16 tag
        // Encrypt empty string and verify
        var encrypted = AegisCrypto.Encrypt("", TestSecret);
        var decrypted = AegisCrypto.Decrypt(encrypted, TestSecret);

        Assert.Equal("", decrypted);
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // BASE64URL ENCODING — Roundtrip and edge cases
    // ═══════════════════════════════════════════════════════════════════════════

    [Theory]
    [InlineData(new byte[] { 0x00 })]
    [InlineData(new byte[] { 0xFF, 0xFE, 0xFD })]
    [InlineData(new byte[] { 0x3E, 0x3F })] // '+' and '/' in standard Base64
    public void ToBase64Url_FromBase64Url_Roundtrip(byte[] data)
    {
        var encoded = AegisCrypto.ToBase64Url(data);
        var decoded = AegisCrypto.FromBase64Url(encoded);

        Assert.Equal(data, decoded);
    }

    [Fact]
    public void ToBase64Url_ContainsNoUnsafeChars()
    {
        // Bytes that would produce +, /, = in standard Base64
        var data = new byte[256];
        for (var i = 0; i < 256; i++) data[i] = (byte)i;

        var encoded = AegisCrypto.ToBase64Url(data);

        Assert.DoesNotContain("+", encoded);
        Assert.DoesNotContain("/", encoded);
        Assert.DoesNotContain("=", encoded);
    }

    [Fact]
    public void ToBase64Url_EmptyBytes_ReturnsEmptyString()
    {
        var encoded = AegisCrypto.ToBase64Url(Array.Empty<byte>());

        Assert.Empty(encoded);
    }

    [Fact]
    public void FromBase64UrlToString_ValidInput_ReturnsString()
    {
        var original = "hello world";
        var encoded = AegisCrypto.ToBase64Url(original);
        var decoded = AegisCrypto.FromBase64UrlToString(encoded);

        Assert.Equal(original, decoded);
    }

    [Fact]
    public void FromBase64UrlToString_InvalidInput_ReturnsNull()
    {
        var decoded = AegisCrypto.FromBase64UrlToString("!!!not-base64!!!");

        Assert.Null(decoded);
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // RANDOM STRING GENERATOR — Entropy and boundary tests
    // ═══════════════════════════════════════════════════════════════════════════

    [Fact]
    public void RandomStringGenerator_DefaultLength_Returns32Chars()
    {
        var result = AegisCrypto.RandomStringGenerator(32, "a-z", "A-Z", "0-9");

        Assert.Equal(32, result.Length);
    }

    [Fact]
    public void RandomStringGenerator_Length1_ReturnsSingleChar()
    {
        var result = AegisCrypto.RandomStringGenerator(1, "a-z");

        Assert.Equal(1, result.Length);
        Assert.InRange(result[0], 'a', 'z');
    }

    [Fact]
    public void RandomStringGenerator_LowerCaseOnly_ContainsOnlyLowerCase()
    {
        var result = AegisCrypto.RandomStringGenerator(100, "a-z");

        Assert.Matches("^[a-z]+$", result);
    }

    [Fact]
    public void RandomStringGenerator_DigitsOnly_ContainsOnlyDigits()
    {
        var result = AegisCrypto.RandomStringGenerator(100, "0-9");

        Assert.Matches("^[0-9]+$", result);
    }

    [Fact]
    public void RandomStringGenerator_TwoCallsProduceDifferentResults()
    {
        var r1 = AegisCrypto.RandomStringGenerator(32, "a-z", "A-Z", "0-9");
        var r2 = AegisCrypto.RandomStringGenerator(32, "a-z", "A-Z", "0-9");

        // Theoretically could be equal, but probability is ~2^-190
        Assert.NotEqual(r2, r1);
    }

    [Fact]
    public void RandomStringGenerator_ZeroLength_Throws()
    {
        Func<string> act = () => AegisCrypto.RandomStringGenerator(0, "a-z");

        Assert.Throws<ArgumentOutOfRangeException>(act);
    }

    [Fact]
    public void RandomStringGenerator_NegativeLength_Throws()
    {
        Func<string> act = () => AegisCrypto.RandomStringGenerator(-1, "a-z");

        Assert.Throws<ArgumentOutOfRangeException>(act);
    }

    [Fact]
    public void RandomStringGenerator_InvalidAlphabet_Throws()
    {
        Func<string> act = () => AegisCrypto.RandomStringGenerator(10, "nonexistent-alphabet");

        Assert.Throws<ArgumentException>(act);
    }

    [Fact]
    public void RandomStringGenerator_NoAlphabets_UsesAll()
    {
        // When no alphabets specified, should use all available characters
        var result = AegisCrypto.RandomStringGenerator(1000);

        // Should contain at least some of each type over 1000 chars
        Assert.Matches("[a-z]", result);
        Assert.Matches("[A-Z]", result);
        Assert.Matches("[0-9]", result);
    }

    [Fact]
    public void RandomStringGenerator_VeryLongString_Succeeds()
    {
        var result = AegisCrypto.RandomStringGenerator(100_000, "a-z", "A-Z", "0-9");

        Assert.Equal(100_000, result.Length);
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // KEY DERIVATION DETERMINISM
    // ═══════════════════════════════════════════════════════════════════════════

    [Fact]
    public void Encrypt_SameSecretDifferentInstance_CanDecrypt()
    {
        // Proves the key derivation is deterministic from the secret
        var encrypted = AegisCrypto.Encrypt("cross-instance", TestSecret);

        // Decrypt using the same secret string (simulating another instance)
        var decrypted = AegisCrypto.Decrypt(encrypted, TestSecret);

        Assert.Equal("cross-instance", decrypted);
    }
}
