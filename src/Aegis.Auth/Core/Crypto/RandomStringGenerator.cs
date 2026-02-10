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

        public static string Generate(int length, params string[] alphabets)
        {
            if (length <= 0)
                throw new ArgumentOutOfRangeException(nameof(length), "Length must be positive.");

            var chars = alphabets.Length == 0
                ? Alphabets.Values.SelectMany(x => x).ToArray()
                : [.. alphabets.Select(a =>
                    Alphabets.TryGetValue(a, out var set) ? set : throw new ArgumentException($"Unknown alphabet: {a}")
                ).SelectMany(x => x)];

            var result = new char[length];
            using var rng = System.Security.Cryptography.RandomNumberGenerator.Create();
            var buffer = new byte[4];

            for (int i = 0; i < length; i++)
            {
                rng.GetBytes(buffer);
                int idx = BitConverter.ToInt32(buffer, 0) & int.MaxValue % chars.Length;
                result[i] = chars[idx];
            }

            return new string(result);
        }
    }
}