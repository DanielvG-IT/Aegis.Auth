using System.Security.Cryptography;
using System.Text;

namespace Aegis.Auth.Core.Crypto;

internal static class AegisSigner
{
    // Just the raw HMAC signature as a string
    public static string GenerateSignature(string payload, string secret)
    {
        var keyBytes = Encoding.UTF8.GetBytes(secret);
        var payloadBytes = Encoding.UTF8.GetBytes(payload);

        using var hmac = new HMACSHA256(keyBytes);
        var hashBytes = hmac.ComputeHash(payloadBytes);

        // Base64Url encoding for signatures
        return ToBase64Url(hashBytes);
    }

    // Helper to ensure the signature is URL/Cookie safe
    private static string ToBase64Url(byte[] bytes)
    {
        return Convert.ToBase64String(bytes)
            .Replace("+", "-")
            .Replace("/", "_")
            .Replace("=", ""); // No padding
    }

    // Standard Sign (Data.Signature) used for the raw Session Token
    public static string Sign(string value, string secret)
    {
        var signature = GenerateSignature(value, secret);
        return $"{value}.{signature}";
    }

    public static bool VerifySignature(string payload, string signature, string secret)
    {
        var expectedSignature = GenerateSignature(payload, secret);

        // Constant-time comparison to prevent timing attacks
        return CryptographicOperations.FixedTimeEquals(
            Encoding.UTF8.GetBytes(signature),
            Encoding.UTF8.GetBytes(expectedSignature));
    }
}