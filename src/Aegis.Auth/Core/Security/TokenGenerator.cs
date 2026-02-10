using System.Security.Cryptography;

namespace Aegis.Auth.Core.Security
{
    /// <summary>
    /// Generates secure random tokens for sessions, verification codes, etc.
    /// </summary>
    public class TokenGenerator
    {
        /// <summary>
        /// Generates a cryptographically secure session token.
        /// </summary>
        public string GenerateSessionToken()
        {
            return GenerateSecureToken(32);
        }

        /// <summary>
        /// Generates a cryptographically secure verification token.
        /// </summary>
        public string GenerateVerificationToken()
        {
            return GenerateSecureToken(32);
        }

        /// <summary>
        /// Generates a secure random token of the specified length.
        /// </summary>
        private static string GenerateSecureToken(int length)
        {
            var bytes = new byte[length];
            using var rng = RandomNumberGenerator.Create();
            rng.GetBytes(bytes);
            return Convert.ToBase64String(bytes).Replace("+", "-").Replace("/", "_").Replace("=", "");
        }
    }
}