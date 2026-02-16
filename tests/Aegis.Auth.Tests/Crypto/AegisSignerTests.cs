using System.Text;

using Aegis.Auth.Core.Crypto;

using FluentAssertions;

namespace Aegis.Auth.Tests.Crypto;

/// <summary>
/// Adversarial test suite for AegisSigner.
/// Focus: HMAC correctness, timing attack resistance (constant-time comparison),
/// signature manipulation, boundary payloads.
/// </summary>
public sealed class AegisSignerTests
{
    private const string TestSecret = "test-secret-that-is-long-enough-for-hmac-256-operations!!";
    private const string AltSecret = "different-secret-that-is-long-enough-for-hmac-256-ops!!";

    // ═══════════════════════════════════════════════════════════════════════════
    // SIGNATURE GENERATION — Determinism
    // ═══════════════════════════════════════════════════════════════════════════

    [Fact]
    public void GenerateSignature_SameInputs_ProducesSameSignature()
    {
        var sig1 = AegisSigner.GenerateSignature("payload", TestSecret);
        var sig2 = AegisSigner.GenerateSignature("payload", TestSecret);

        sig1.Should().Be(sig2, "HMAC must be deterministic for the same inputs");
    }

    [Fact]
    public void GenerateSignature_DifferentPayloads_ProduceDifferentSignatures()
    {
        var sig1 = AegisSigner.GenerateSignature("payload-a", TestSecret);
        var sig2 = AegisSigner.GenerateSignature("payload-b", TestSecret);

        sig1.Should().NotBe(sig2);
    }

    [Fact]
    public void GenerateSignature_DifferentSecrets_ProduceDifferentSignatures()
    {
        var sig1 = AegisSigner.GenerateSignature("payload", TestSecret);
        var sig2 = AegisSigner.GenerateSignature("payload", AltSecret);

        sig1.Should().NotBe(sig2);
    }

    [Fact]
    public void GenerateSignature_IsBase64UrlSafe()
    {
        var sig = AegisSigner.GenerateSignature("some data", TestSecret);

        sig.Should().NotContain("+");
        sig.Should().NotContain("/");
        sig.Should().NotContain("=");
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // SIGN — Format: value.signature
    // ═══════════════════════════════════════════════════════════════════════════

    [Fact]
    public void Sign_ProducesDotSeparatedFormat()
    {
        var signed = AegisSigner.Sign("token-value", TestSecret);

        signed.Should().Contain(".");
        var parts = signed.Split('.');
        parts.Should().HaveCount(2);
        parts[0].Should().Be("token-value");
        parts[1].Should().NotBeNullOrWhiteSpace();
    }

    [Fact]
    public void Sign_SignaturePartMatchesGenerateSignature()
    {
        var signed = AegisSigner.Sign("my-token", TestSecret);
        var expectedSig = AegisSigner.GenerateSignature("my-token", TestSecret);

        var signaturePart = signed.Split('.')[1];
        signaturePart.Should().Be(expectedSig);
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // VERIFY SIGNATURE — Happy path
    // ═══════════════════════════════════════════════════════════════════════════

    [Fact]
    public void VerifySignature_ValidSignature_ReturnsTrue()
    {
        var signature = AegisSigner.GenerateSignature("payload", TestSecret);

        var result = AegisSigner.VerifySignature("payload", signature, TestSecret);

        result.Should().BeTrue();
    }

    [Fact]
    public void VerifySignature_SignedToken_CanBeVerified()
    {
        var signed = AegisSigner.Sign("session-token-xyz", TestSecret);
        var parts = signed.Split('.');

        var result = AegisSigner.VerifySignature(parts[0], parts[1], TestSecret);

        result.Should().BeTrue();
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // WRONG SECRET — Key mismatch
    // ═══════════════════════════════════════════════════════════════════════════

    [Fact]
    public void VerifySignature_WrongSecret_ReturnsFalse()
    {
        var signature = AegisSigner.GenerateSignature("payload", TestSecret);

        var result = AegisSigner.VerifySignature("payload", signature, AltSecret);

        result.Should().BeFalse();
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // SIGNATURE MANIPULATION — Tampered signatures
    // ═══════════════════════════════════════════════════════════════════════════

    [Fact]
    public void VerifySignature_FlippedBit_ReturnsFalse()
    {
        var signature = AegisSigner.GenerateSignature("payload", TestSecret);

        // Flip one character
        var chars = signature.ToCharArray();
        chars[0] = chars[0] == 'A' ? 'B' : 'A';
        var tampered = new string(chars);

        var result = AegisSigner.VerifySignature("payload", tampered, TestSecret);

        result.Should().BeFalse();
    }

    [Fact]
    public void VerifySignature_TruncatedSignature_ReturnsFalse()
    {
        var signature = AegisSigner.GenerateSignature("payload", TestSecret);
        var truncated = signature[..^3];

        var result = AegisSigner.VerifySignature("payload", truncated, TestSecret);

        result.Should().BeFalse();
    }

    [Fact]
    public void VerifySignature_ExtendedSignature_ReturnsFalse()
    {
        var signature = AegisSigner.GenerateSignature("payload", TestSecret);
        var extended = signature + "AAA";

        var result = AegisSigner.VerifySignature("payload", extended, TestSecret);

        result.Should().BeFalse();
    }

    [Fact]
    public void VerifySignature_EmptySignature_ReturnsFalse()
    {
        var result = AegisSigner.VerifySignature("payload", "", TestSecret);

        result.Should().BeFalse();
    }

    [Fact]
    public void VerifySignature_CompletelyRandomSignature_ReturnsFalse()
    {
        var result = AegisSigner.VerifySignature("payload", "totally-random-garbage", TestSecret);

        result.Should().BeFalse();
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // PAYLOAD MANIPULATION — Correct signature but wrong payload
    // ═══════════════════════════════════════════════════════════════════════════

    [Fact]
    public void VerifySignature_ModifiedPayload_ReturnsFalse()
    {
        var signature = AegisSigner.GenerateSignature("original-payload", TestSecret);

        var result = AegisSigner.VerifySignature("modified-payload", signature, TestSecret);

        result.Should().BeFalse();
    }

    [Fact]
    public void VerifySignature_PayloadWithAppendedChar_ReturnsFalse()
    {
        var signature = AegisSigner.GenerateSignature("payload", TestSecret);

        var result = AegisSigner.VerifySignature("payload ", signature, TestSecret);

        result.Should().BeFalse("trailing space changes the HMAC");
    }

    [Fact]
    public void VerifySignature_EmptyPayload_ValidSignature_ReturnsTrue()
    {
        var signature = AegisSigner.GenerateSignature("", TestSecret);

        var result = AegisSigner.VerifySignature("", signature, TestSecret);

        result.Should().BeTrue();
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // BOUNDARY PAYLOADS
    // ═══════════════════════════════════════════════════════════════════════════

    [Fact]
    public void Sign_EmptyPayload_Succeeds()
    {
        var signed = AegisSigner.Sign("", TestSecret);

        signed.Should().StartWith(".");
        var parts = signed.Split('.');
        parts[0].Should().BeEmpty();
        parts[1].Should().NotBeNullOrWhiteSpace();
    }

    [Fact]
    public void Sign_PayloadContainingDots_SignatureIsLastDotSegment()
    {
        // The payload itself contains dots — Sign just appends .signature
        var signed = AegisSigner.Sign("part1.part2.part3", TestSecret);

        // Should be "part1.part2.part3.<signature>"
        var lastDot = signed.LastIndexOf('.');
        var payload = signed[..lastDot];
        var sig = signed[(lastDot + 1)..];

        payload.Should().Be("part1.part2.part3");
        AegisSigner.VerifySignature(payload, sig, TestSecret).Should().BeTrue();
    }

    [Fact]
    public void GenerateSignature_UnicodePayload_HandledCorrectly()
    {
        var sig = AegisSigner.GenerateSignature("日本語テスト🔐", TestSecret);

        sig.Should().NotBeNullOrWhiteSpace();
        AegisSigner.VerifySignature("日本語テスト🔐", sig, TestSecret).Should().BeTrue();
    }

    [Fact]
    public void GenerateSignature_VeryLargePayload_Succeeds()
    {
        var largePayload = new string('X', 2 * 1024 * 1024); // 2MB

        var sig = AegisSigner.GenerateSignature(largePayload, TestSecret);

        sig.Should().NotBeNullOrWhiteSpace();
        AegisSigner.VerifySignature(largePayload, sig, TestSecret).Should().BeTrue();
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // CONSTANT-TIME COMPARISON — Verify uses FixedTimeEquals
    // We can't directly measure timing, but we can verify the behavior contract:
    // equal-length mismatched signatures must still return false.
    // ═══════════════════════════════════════════════════════════════════════════

    [Fact]
    public void VerifySignature_SameLengthWrongSignature_ReturnsFalse()
    {
        var realSig = AegisSigner.GenerateSignature("payload", TestSecret);
        // Create a same-length but different signature
        var fakeSig = new string('A', realSig.Length);

        var result = AegisSigner.VerifySignature("payload", fakeSig, TestSecret);

        result.Should().BeFalse();
    }

    [Fact]
    public void VerifySignature_SignatureFromDifferentPayload_ReturnsFalse()
    {
        var sigForA = AegisSigner.GenerateSignature("payload-A", TestSecret);

        // Use signature from payload-A to verify payload-B (replay attack)
        var result = AegisSigner.VerifySignature("payload-B", sigForA, TestSecret);

        result.Should().BeFalse();
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // SIGNATURE LENGTH — HMAC-SHA256 always produces 32 bytes
    // ═══════════════════════════════════════════════════════════════════════════

    [Theory]
    [InlineData("short")]
    [InlineData("")]
    [InlineData("a very long payload that goes on and on and on and on and on")]
    public void GenerateSignature_AlwaysProducesSameLength(string payload)
    {
        var sig = AegisSigner.GenerateSignature(payload, TestSecret);

        // HMAC-SHA256 = 32 bytes. Base64Url of 32 bytes = ceil(32*4/3) = 43 chars (no padding)
        sig.Should().HaveLength(43, "HMAC-SHA256 base64url is always 43 chars");
    }
}
