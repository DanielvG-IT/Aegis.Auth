using System.Security.Cryptography;
using System.Text;

namespace Aegis.Auth.Core.Crypto;

/// <summary>
/// Stateless AES-256-GCM encryption using a key derived from the application secret via HKDF.
/// Every instance sharing the same secret can encrypt/decrypt — no shared key ring or state required.
/// </summary>
internal static class AegisCrypto
{
  private const int NonceSize = 12;  // AES-GCM standard nonce
  private const int TagSize = 16;    // 128-bit authentication tag
  private const int KeySize = 32;    // AES-256
  private static readonly byte[] HkdfInfo = "Aegis.Auth.CookieCache.v1"u8.ToArray();

  /// <summary>
  /// Encrypts plaintext with AES-256-GCM. Output: Base64Url(nonce ‖ ciphertext ‖ tag).
  /// The authentication tag guarantees both confidentiality and integrity.
  /// </summary>
  public static string Encrypt(string plaintext, string secret)
  {
    var key = DeriveKey(secret);
    var plaintextBytes = Encoding.UTF8.GetBytes(plaintext);
    var nonce = RandomNumberGenerator.GetBytes(NonceSize);
    var ciphertext = new byte[plaintextBytes.Length];
    var tag = new byte[TagSize];

    using var aes = new AesGcm(key, TagSize);
    aes.Encrypt(nonce, plaintextBytes, ciphertext, tag);

    // Wire format: [12-byte nonce][ciphertext][16-byte tag]
    var result = new byte[NonceSize + ciphertext.Length + TagSize];
    Buffer.BlockCopy(nonce, 0, result, 0, NonceSize);
    Buffer.BlockCopy(ciphertext, 0, result, NonceSize, ciphertext.Length);
    Buffer.BlockCopy(tag, 0, result, NonceSize + ciphertext.Length, TagSize);

    return ToBase64Url(result);
  }

  /// <summary>
  /// Decrypts a payload produced by <see cref="Encrypt"/>.
  /// Returns null if the payload is tampered, truncated, or the secret doesn't match.
  /// </summary>
  public static string? Decrypt(string encoded, string secret)
  {
    try
    {
      var key = DeriveKey(secret);
      var data = FromBase64Url(encoded);

      if (data.Length < NonceSize + TagSize)
        return null;

      var nonce = data.AsSpan(0, NonceSize).ToArray();
      var ciphertext = data.AsSpan(NonceSize, data.Length - NonceSize - TagSize).ToArray();
      var tag = data.AsSpan(data.Length - TagSize, TagSize).ToArray();
      var plaintext = new byte[ciphertext.Length];

      using var aes = new AesGcm(key, TagSize);
      aes.Decrypt(nonce, ciphertext, tag, plaintext);

      return Encoding.UTF8.GetString(plaintext);
    }
    catch (CryptographicException)
    {
      return null; // Tampered or wrong key
    }
  }

  // ── Base64Url helpers (cookie/URL safe, no padding) ──────────────────────

  public static string ToBase64Url(byte[] data)
  {
    return Convert.ToBase64String(data)
        .Replace("+", "-")
        .Replace("/", "_")
        .TrimEnd('=');
  }

  public static string ToBase64Url(string plaintext)
  {
    return ToBase64Url(Encoding.UTF8.GetBytes(plaintext));
  }

  public static byte[] FromBase64Url(string encoded)
  {
    var base64 = encoded.Replace("-", "+").Replace("_", "/");
    switch (base64.Length % 4)
    {
      case 2: base64 += "=="; break;
      case 3: base64 += "="; break;
    }
    return Convert.FromBase64String(base64);
  }

  // ── Key derivation ───────────────────────────────────────────────────────

  private static byte[] DeriveKey(string secret)
  {
    return HKDF.DeriveKey(
        HashAlgorithmName.SHA256,
        Encoding.UTF8.GetBytes(secret),
        KeySize,
        info: HkdfInfo);
  }

  // ── RandomStringGenerator ────────────────────────────────────────────────
  private static readonly Dictionary<string, string> Alphabets = new()
        {
            { "a-z", "abcdefghijklmnopqrstuvwxyz" },
            { "A-Z", "ABCDEFGHIJKLMNOPQRSTUVWXYZ" },
            { "0-9", "0123456789" },
            { "-_", "-_" }
        };

  public static string RandomStringGenerator(int length = 32, params string[] alphabets)
  {
    if (length <= 0)
      throw new ArgumentOutOfRangeException(nameof(length), "Length must be positive.");

    // Build the character set. If no alphabets passed, use them all.
    var characterSet = alphabets.Length == 0
        ? string.Join("", Alphabets.Values)
        : string.Join("", alphabets.Select(key => Alphabets.TryGetValue(key, out var val) ? val : ""));

    if (string.IsNullOrEmpty(characterSet))
      throw new ArgumentException("Character set cannot be empty.");

    var charArray = characterSet.ToCharArray();

    return string.Create(length, charArray, (span, chars) =>
    {
      for (var i = 0; i < span.Length; i++)
      {
        var randomIndex = RandomNumberGenerator.GetInt32(chars.Length);
        span[i] = chars[randomIndex];
      }
    });
  }
}
