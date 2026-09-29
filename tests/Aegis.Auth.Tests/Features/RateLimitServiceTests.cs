using System.Net;

using Aegis.Auth.Features.RateLimit;
using Aegis.Auth.Options;

namespace Aegis.Auth.Tests.Features;

public sealed class RateLimitServiceTests
{
    private static RateLimitService Create(int perIp = 3, int perEmail = 2, bool enabled = true) =>
        new(Microsoft.Extensions.Options.Options.Create(new AegisAuthOptions
        {
            RateLimit = new RateLimitOptions
            {
                Enabled = enabled,
                MaxAttemptsPerIpPerMinute = perIp,
                MaxAttemptsPerEmailPer15Minutes = perEmail,
            },
        }));

    // ═══════════════════════════════════════════════════════════════════════════
    // CLIENT PARTITION KEYS
    // ═══════════════════════════════════════════════════════════════════════════

    [Theory]
    [InlineData("203.0.113.7", "203.0.113.7")]
    [InlineData("::ffff:203.0.113.7", "203.0.113.7")]
    [InlineData("2001:db8:1:2:aaaa:bbbb:cccc:dddd", "2001:db8:1:2::/64")]
    [InlineData("2001:db8:1:2::1", "2001:db8:1:2::/64")]
    [InlineData("::1", "::/64")]
    public void GetClientPartitionKey_NormalizesAddress(string address, string expected)
    {
        Assert.Equal(expected, RateLimitService.GetClientPartitionKey(IPAddress.Parse(address)));
    }

    [Fact]
    public void GetClientPartitionKey_DifferentIpv6Prefixes_AreSeparateClients()
    {
        Assert.NotEqual(
            RateLimitService.GetClientPartitionKey(IPAddress.Parse("2001:db8:1:2::1")),
            RateLimitService.GetClientPartitionKey(IPAddress.Parse("2001:db8:1:3::1")));
    }

    [Fact]
    public void GetClientPartitionKey_NullAddress_SharesUnknownBucket()
    {
        Assert.Equal("unknown", RateLimitService.GetClientPartitionKey(null));
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // LIMITS
    // ═══════════════════════════════════════════════════════════════════════════

    [Fact]
    public void TryAcquireForClient_AllowsExactlyConfiguredLimit()
    {
        using RateLimitService sut = Create(perIp: 3);
        IPAddress client = IPAddress.Parse("203.0.113.7");

        for (var i = 0; i < 3; i++)
        {
            Assert.True(sut.TryAcquireForClient("sign-in-email", client).IsAllowed);
        }

        RateLimitDecision rejected = sut.TryAcquireForClient("sign-in-email", client);

        Assert.False(rejected.IsAllowed);
        Assert.NotNull(rejected.RetryAfter);
        Assert.True(rejected.RetryAfter <= TimeSpan.FromMinutes(1));
    }

    [Fact]
    public void TryAcquireForClient_OperationsHaveSeparateBudgets()
    {
        using RateLimitService sut = Create(perIp: 1);
        IPAddress client = IPAddress.Parse("203.0.113.7");

        Assert.True(sut.TryAcquireForClient("sign-in-email", client).IsAllowed);
        Assert.False(sut.TryAcquireForClient("sign-in-email", client).IsAllowed);
        Assert.True(sut.TryAcquireForClient("sign-up-email", client).IsAllowed);
    }

    [Fact]
    public void TryAcquireForEmail_AllowsExactlyConfiguredLimit()
    {
        using RateLimitService sut = Create(perEmail: 2);

        Assert.True(sut.TryAcquireForEmail("user@test.com").IsAllowed);
        Assert.True(sut.TryAcquireForEmail("user@test.com").IsAllowed);
        RateLimitDecision rejected = sut.TryAcquireForEmail("user@test.com");

        Assert.False(rejected.IsAllowed);
        Assert.True(rejected.RetryAfter <= TimeSpan.FromMinutes(15));
        Assert.True(sut.TryAcquireForEmail("other@test.com").IsAllowed);
    }

    [Fact]
    public void Disabled_AlwaysAllows_EvenWithInvalidLimits()
    {
        using RateLimitService sut = Create(perIp: 0, perEmail: 0, enabled: false);

        for (var i = 0; i < 20; i++)
        {
            Assert.True(sut.TryAcquireForClient("sign-in-email", IPAddress.Loopback).IsAllowed);
            Assert.True(sut.TryAcquireForEmail("user@test.com").IsAllowed);
        }
    }
}
