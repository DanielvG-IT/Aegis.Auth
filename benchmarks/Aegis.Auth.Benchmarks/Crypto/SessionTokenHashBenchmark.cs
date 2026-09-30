using Aegis.Auth.Core.Crypto;

using BenchmarkDotNet.Attributes;

namespace Aegis.Auth.Benchmarks.Crypto;

/// <summary>
/// <c>AegisCrypto.HashToken</c> runs on every request that falls through to the database, and on every token consume.
/// </summary>
[BenchmarkCategory("Crypto")]
public class SessionTokenHashBenchmark
{
    private string _token = string.Empty;

    [GlobalSetup]
    public void Setup()
    {
        // Same shape as SessionService: 32 alphanumeric characters.
        _token = AegisCrypto.RandomStringGenerator(32, "a-z", "A-Z", "0-9");
    }

    [Benchmark]
    public string HashToken() => AegisCrypto.HashToken(_token);

    [Benchmark]
    public string GenerateToken() => AegisCrypto.RandomStringGenerator(32, "a-z", "A-Z", "0-9");
}
