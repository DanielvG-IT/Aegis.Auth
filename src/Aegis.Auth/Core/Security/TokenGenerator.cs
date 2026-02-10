using System.Security.Cryptography;

namespace Aegis.Auth.Core.Security
{
    internal static class TokenGenerator
    {
        /// <summary>
        /// Generates a cryptographically secure random token
        /// </summary>
        /// <param name="length">Length of the token in bytes (default: 32)</param>
        /// <returns>Base64url encoded token string</returns>
        public static string GenerateToken(int length = 32)
        {
            var bytes = new byte[length];
            RandomNumberGenerator.Fill(bytes);

            // Convert to base64url (URL-safe base64)
            return Convert.ToBase64String(bytes)
                .Replace("+", "-")
                .Replace("/", "_")
                .Replace("=", "");
        }
    }
}