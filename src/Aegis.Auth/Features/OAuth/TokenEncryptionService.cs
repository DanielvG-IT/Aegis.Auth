using Microsoft.AspNetCore.DataProtection;

namespace Aegis.Auth.Features.OAuth;

/// <summary>
/// Encrypts/decrypts OAuth tokens (access tokens, refresh tokens, ID tokens)
/// using ASP.NET Core's built-in Data Protection API.
/// Safe for multi-instance deployments (DPAPI uses app-level keys, not machine-level).
/// </summary>
internal sealed class TokenEncryptionService(IDataProtectionProvider dataProtectionProvider) : ITokenEncryptionService
{
    private readonly IDataProtector _protector = dataProtectionProvider.CreateProtector("Aegis.Auth.TokenEncryption");

    public string EncryptToken(string? plaintext)
    {
        if (string.IsNullOrWhiteSpace(plaintext))
            return string.Empty;

        try
        {
            return _protector.Protect(plaintext);
        }
        catch
        {
            // If encryption fails, return empty to fail safely
            return string.Empty;
        }
    }

    public string? DecryptToken(string? ciphertext)
    {
        if (string.IsNullOrWhiteSpace(ciphertext))
            return null;

        try
        {
            return _protector.Unprotect(ciphertext);
        }
        catch
        {
            // If decryption fails (corrupted data, key not available), return null
            return null;
        }
    }
}
