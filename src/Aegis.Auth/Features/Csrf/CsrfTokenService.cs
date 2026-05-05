using Aegis.Auth.Core.Crypto;
using Aegis.Auth.Options;

using Microsoft.Extensions.Options;

namespace Aegis.Auth.Features.Csrf;

public interface ICsrfTokenService
{
    /// <summary>
    /// Generates a new CSRF token. The caller should store the raw token in a signed cookie
    /// and return it to the client. The client includes it in X-CSRF-Token header on state-changing requests.
    /// </summary>
    string GenerateToken();

    /// <summary>
    /// Validates a CSRF token from the request header against the signed cookie value.
    /// Returns true if valid and matches; false otherwise.
    /// </summary>
    bool ValidateToken(string headerToken, string cookieToken);
}

internal sealed class CsrfTokenService(IOptions<AegisAuthOptions> optionsAccessor) : ICsrfTokenService
{
    private readonly AegisAuthOptions _options = optionsAccessor.Value;

    public string GenerateToken()
    {
        // Generate a 32-char random token like session tokens
        return AegisCrypto.RandomStringGenerator(32, "a-z", "A-Z", "0-9");
    }

    public bool ValidateToken(string headerToken, string cookieToken)
    {
        if (string.IsNullOrWhiteSpace(headerToken) || string.IsNullOrWhiteSpace(cookieToken))
            return false;

        // The cookie contains "token.signature" from AegisSigner.Sign().
        // Extract the raw token from the cookie, then compare with the header token.
        var dotIndex = cookieToken.LastIndexOf('.');
        if (dotIndex <= 0 || dotIndex >= cookieToken.Length - 1)
            return false;

        var rawTokenFromCookie = cookieToken[..dotIndex];
        var signatureFromCookie = cookieToken[(dotIndex + 1)..];

        // Verify the signature on the cookie value
        if (!AegisSigner.VerifySignature(rawTokenFromCookie, signatureFromCookie, _options.Secret))
            return false;

        // Compare the cookie token with the header token (both raw, not signatures)
        return string.Equals(rawTokenFromCookie, headerToken, StringComparison.Ordinal);
    }
}
