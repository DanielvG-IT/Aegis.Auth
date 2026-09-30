using Aegis.Auth.Core.Crypto;

using BenchmarkDotNet.Attributes;

namespace Aegis.Auth.Benchmarks.Crypto;

/// <summary>
/// HMAC-SHA256 signing of the session cookie (<c>token.signature</c>). Verify runs on every authenticated request.
/// </summary>
[BenchmarkCategory("Crypto")]
public class CookieSignBenchmark
{
    private const string Secret = "benchmark-secret-that-is-long-enough-for-hmac-256!!";

    private string _token = string.Empty;
    private string _signature = string.Empty;

    [GlobalSetup]
    public void Setup()
    {
        _token = AegisCrypto.RandomStringGenerator(32, "a-z", "A-Z", "0-9");
        _signature = AegisSigner.GenerateSignature(_token, Secret);
    }

    [Benchmark]
    public string Sign() => AegisSigner.Sign(_token, Secret);

    [Benchmark]
    public bool Verify() => AegisSigner.VerifySignature(_token, _signature, Secret);
}
