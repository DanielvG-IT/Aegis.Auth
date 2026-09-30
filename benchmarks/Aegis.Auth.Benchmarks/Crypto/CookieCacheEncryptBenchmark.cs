using System.Text.Json;

using Aegis.Auth.Core.Crypto;
using Aegis.Auth.Entities;
using Aegis.Auth.Extensions;
using Aegis.Auth.Models;

using BenchmarkDotNet.Attributes;

namespace Aegis.Auth.Benchmarks.Crypto;

/// <summary>
/// AES-256-GCM protection of the <c>session_data</c> cookie (<see cref="Aegis.Auth.Options.CookieCacheMode.Encrypted"/>),
/// against the Base64Url encoding of <see cref="Aegis.Auth.Options.CookieCacheMode.Compact"/>. The payload is the
/// real envelope <c>SessionCookieHandler</c> writes.
/// </summary>
[BenchmarkCategory("Crypto")]
public class CookieCacheEncryptBenchmark
{
    private const string Secret = "benchmark-secret-that-is-long-enough-for-hmac-256!!";

    private string _payload = string.Empty;
    private string _encrypted = string.Empty;
    private string _compact = string.Empty;

    [GlobalSetup]
    public void Setup()
    {
        DateTime now = DateTime.UtcNow;
        var user = new User { Id = "user-000001", Name = "Bench User", Email = "user@bench.aegis.local", EmailVerified = true, CreatedAt = now, UpdatedAt = now };
        var session = new Session
        {
            Id = Guid.CreateVersion7().ToString(),
            Token = AegisCrypto.RandomStringGenerator(32, "a-z", "A-Z", "0-9"),
            UserId = user.Id,
            ExpiresAt = now.AddDays(7),
            IpAddress = "203.0.113.10",
            UserAgent = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0 Safari/537.36",
            CreatedAt = now,
            UpdatedAt = now,
        };
        var sessionPayload = new SessionCacheDto
        {
            Session = new() { Session = session.ToDto(), User = user.ToDto() },
            UpdatedAt = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
        };
        var expiresAt = DateTimeOffset.UtcNow.AddMinutes(5).ToUnixTimeMilliseconds();
        var signature = AegisSigner.GenerateSignature(JsonSerializer.Serialize(new { ExpiresAt = expiresAt, Session = sessionPayload }), Secret);

        _payload = JsonSerializer.Serialize(new SessionCachePayload { Signature = signature, Session = sessionPayload, ExpiresAt = expiresAt });
        _encrypted = AegisCrypto.Encrypt(_payload, Secret);
        _compact = AegisCrypto.ToBase64Url(_payload);
    }

    [Benchmark]
    public string Encrypt() => AegisCrypto.Encrypt(_payload, Secret);

    [Benchmark]
    public string? Decrypt() => AegisCrypto.Decrypt(_encrypted, Secret);

    [Benchmark]
    public string CompactEncode() => AegisCrypto.ToBase64Url(_payload);

    [Benchmark]
    public string? CompactDecode() => AegisCrypto.FromBase64UrlToString(_compact);
}
