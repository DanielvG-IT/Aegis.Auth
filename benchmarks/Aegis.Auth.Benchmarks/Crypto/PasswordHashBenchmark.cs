using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Engines;

namespace Aegis.Auth.Benchmarks.Crypto;

/// <summary>
/// BCrypt cost per work factor, using the same <c>EnhancedHashPassword</c> / <c>EnhancedVerify</c> calls as the
/// default <c>PasswordOptions</c> (whose work factor is BCrypt.Net's default, 11). Each step doubles the cost,
/// so a short job is enough and keeps work factor 14 from dominating the run.
/// </summary>
[BenchmarkCategory("Crypto", "Password")]
[SimpleJob(RunStrategy.Monitoring, launchCount: 1, warmupCount: 1, iterationCount: 5)]
public class PasswordHashBenchmark
{
    private const string Password = "correct horse battery staple";

    private string _hash = string.Empty;

    [Params(10, 11, 12, 14)]
    public int WorkFactor { get; set; }

    [GlobalSetup]
    public void Setup()
    {
        _hash = BCrypt.Net.BCrypt.EnhancedHashPassword(Password, WorkFactor);
    }

    [Benchmark]
    public string Hash() => BCrypt.Net.BCrypt.EnhancedHashPassword(Password, WorkFactor);

    [Benchmark]
    public bool Verify() => BCrypt.Net.BCrypt.EnhancedVerify(Password, _hash);
}
