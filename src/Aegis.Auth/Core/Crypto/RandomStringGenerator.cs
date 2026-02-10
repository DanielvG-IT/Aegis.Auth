using System.Security.Cryptography;

namespace Aegis.Auth.Core.Crypto
{
    public static class RandomStringGenerator
    {
        private static readonly Dictionary<string, string> Alphabets = new()
        {
            { "a-z", "abcdefghijklmnopqrstuvwxyz" },
            { "A-Z", "ABCDEFGHIJKLMNOPQRSTUVWXYZ" },
            { "0-9", "0123456789" },
            { "-_", "-_" }
        };

        public static string Generate(int length = 32, params string[] alphabets)
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
}