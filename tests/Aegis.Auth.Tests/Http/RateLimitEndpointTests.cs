using System.Net;
using System.Net.Http.Json;
using System.Text;
using System.Text.Json;

using Aegis.Auth.Constants;

namespace Aegis.Auth.Tests.Http;

/// <summary>
/// End-to-end checks that <see cref="Aegis.Auth.Options.RateLimitOptions"/> is enforced on the auth endpoints.
/// </summary>
public sealed class RateLimitEndpointTests
{
    private const string Email = "limit@test.com";

    // Built at runtime so secret scanners don't flag test fixtures as leaked credentials.
    private static readonly string GoodCredential = new('c', 16);
    private static readonly string BadCredential = new('w', 16);

    public static TheoryData<string, string> LimitedEndpoints => new()
    {
        { "/api/auth/sign-in/email", JsonSerializer.Serialize(new { email = Email, password = BadCredential }) },
        { "/api/auth/sign-up/email", JsonSerializer.Serialize(new { name = "Limit", email = Email, password = GoodCredential }) },
        { "/api/auth/password-reset/send-token", $$"""{"email":"{{Email}}"}""" },
        { "/api/auth/password-reset/reset", JsonSerializer.Serialize(new { token = "token", newPassword = GoodCredential }) },
        { "/api/auth/email-verify/send-token", "{}" },
        { "/api/auth/email-verify/verify", """{"token":"token"}""" },
    };

    private static Task<AegisTestHost> StartAsync(int perIp = 100, int perEmail = 100, bool enabled = true) =>
        AegisTestHost.StartAsync(o =>
        {
            // Password reset and email verification endpoints are only mapped when their delivery delegates are configured.
            o.EmailAndPassword.SendResetPassword = (_, _) => Task.CompletedTask;
            o.EmailVerification.SendVerificationEmail = (_, _) => Task.CompletedTask;
            o.RateLimit.Enabled = enabled;
            o.RateLimit.MaxAttemptsPerIpPerMinute = perIp;
            o.RateLimit.MaxAttemptsPerEmailPer15Minutes = perEmail;
        });

    private static Task<HttpResponseMessage> PostAsync(AegisTestHost host, string path, string json, string? clientIp = null)
    {
        var request = new HttpRequestMessage(HttpMethod.Post, path)
        {
            Content = new StringContent(json, Encoding.UTF8, "application/json"),
        };
        if (clientIp is not null)
        {
            request.Headers.Add(AegisTestHost.ClientIpHeader, clientIp);
        }

        return host.Client.SendAsync(request);
    }

    private static Task<HttpResponseMessage> SignInAsync(AegisTestHost host, string password, string? clientIp = null, string email = Email) =>
        PostAsync(host, "/api/auth/sign-in/email", JsonSerializer.Serialize(new { email, password }), clientIp);

    private static Task<HttpResponseMessage> SignUpAsync(AegisTestHost host, string email = Email, string? clientIp = null) =>
        PostAsync(host, "/api/auth/sign-up/email", JsonSerializer.Serialize(new { name = "Limit", email, password = GoodCredential }), clientIp);

    private static async Task AssertTooManyRequestsAsync(HttpResponseMessage response)
    {
        Assert.Equal(HttpStatusCode.TooManyRequests, response.StatusCode);
        Assert.Equal("application/problem+json", response.Content.Headers.ContentType?.MediaType);

        using JsonDocument body = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        Assert.Equal(429, body.RootElement.GetProperty("status").GetInt32());
        Assert.Equal(AuthErrors.RateLimit.TooManyRequests, body.RootElement.GetProperty("errorCode").GetString());
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // PER-IP LIMIT
    // ═══════════════════════════════════════════════════════════════════════════

    [Theory]
    [MemberData(nameof(LimitedEndpoints))]
    public async Task Endpoint_ClientOverIpLimit_Returns429WithRetryAfter(string path, string json)
    {
        await using AegisTestHost host = await StartAsync(perIp: 3);

        for (var i = 0; i < 3; i++)
        {
            HttpResponseMessage allowed = await PostAsync(host, path, json);
            Assert.NotEqual(HttpStatusCode.TooManyRequests, allowed.StatusCode);
        }

        HttpResponseMessage rejected = await PostAsync(host, path, json);

        await AssertTooManyRequestsAsync(rejected);
        TimeSpan? retryAfter = rejected.Headers.RetryAfter?.Delta;
        Assert.NotNull(retryAfter);
        Assert.InRange(retryAfter.Value, TimeSpan.FromSeconds(1), TimeSpan.FromMinutes(1));
    }

    [Fact]
    public async Task IpLimit_DefaultOptions_AllowsTenRequestsPerMinute()
    {
        await using AegisTestHost host = await AegisTestHost.StartAsync();

        for (var i = 0; i < 10; i++)
        {
            HttpResponseMessage allowed = await SignUpAsync(host, $"user{i}@test.com");
            Assert.Equal(HttpStatusCode.OK, allowed.StatusCode);
        }

        await AssertTooManyRequestsAsync(await SignUpAsync(host, "user10@test.com"));
    }

    [Fact]
    public async Task IpLimit_IsTrackedPerClientIp()
    {
        await using AegisTestHost host = await StartAsync(perIp: 2);

        await SignInAsync(host, BadCredential, "203.0.113.1");
        await SignInAsync(host, BadCredential, "203.0.113.1");
        HttpResponseMessage limitedClient = await SignInAsync(host, BadCredential, "203.0.113.1");
        HttpResponseMessage otherClient = await SignInAsync(host, BadCredential, "203.0.113.2");

        await AssertTooManyRequestsAsync(limitedClient);
        Assert.Equal(HttpStatusCode.Unauthorized, otherClient.StatusCode);
    }

    [Fact]
    public async Task IpLimit_IsTrackedPerEndpoint()
    {
        await using AegisTestHost host = await StartAsync(perIp: 2);

        await SignInAsync(host, BadCredential);
        await SignInAsync(host, BadCredential);
        await AssertTooManyRequestsAsync(await SignInAsync(host, BadCredential));

        HttpResponseMessage signUp = await SignUpAsync(host);

        Assert.Equal(HttpStatusCode.OK, signUp.StatusCode);
    }

    [Fact]
    public async Task IpLimit_GroupsIpv6ClientsBySlash64()
    {
        await using AegisTestHost host = await StartAsync(perIp: 2);

        await SignInAsync(host, BadCredential, "2001:db8:0:1::1");
        await SignInAsync(host, BadCredential, "2001:db8:0:1::2");
        HttpResponseMessage samePrefix = await SignInAsync(host, BadCredential, "2001:db8:0:1:ffff::3");
        HttpResponseMessage otherPrefix = await SignInAsync(host, BadCredential, "2001:db8:0:2::1");

        await AssertTooManyRequestsAsync(samePrefix);
        Assert.Equal(HttpStatusCode.Unauthorized, otherPrefix.StatusCode);
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // PER-EMAIL LIMIT (SIGN-IN)
    // ═══════════════════════════════════════════════════════════════════════════

    [Fact]
    public async Task EmailLimit_DefaultOptions_AllowsFiveAttemptsFromRotatingIps()
    {
        await using AegisTestHost host = await AegisTestHost.StartAsync();

        for (var i = 0; i < 5; i++)
        {
            HttpResponseMessage allowed = await SignInAsync(host, BadCredential, $"198.51.100.{i}");
            Assert.Equal(HttpStatusCode.Unauthorized, allowed.StatusCode);
        }

        await AssertTooManyRequestsAsync(await SignInAsync(host, BadCredential, "198.51.100.99"));
    }

    [Fact]
    public async Task EmailLimit_Reached_RejectsCorrectPasswordToo()
    {
        await using AegisTestHost host = await StartAsync(perEmail: 2);
        Assert.Equal(HttpStatusCode.OK, (await SignUpAsync(host)).StatusCode);

        await SignInAsync(host, BadCredential, "198.51.100.1");
        await SignInAsync(host, BadCredential, "198.51.100.2");
        HttpResponseMessage correctAttempt = await SignInAsync(host, GoodCredential, "198.51.100.3");

        await AssertTooManyRequestsAsync(correctAttempt);
        Assert.False(correctAttempt.Headers.Contains("Set-Cookie"));
    }

    [Fact]
    public async Task EmailLimit_DoesNotAffectOtherEmails()
    {
        await using AegisTestHost host = await StartAsync(perEmail: 1);

        await SignInAsync(host, BadCredential);
        await AssertTooManyRequestsAsync(await SignInAsync(host, BadCredential));

        HttpResponseMessage otherEmail = await SignInAsync(host, BadCredential, email: "other@test.com");

        Assert.Equal(HttpStatusCode.Unauthorized, otherEmail.StatusCode);
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // CONFIGURATION
    // ═══════════════════════════════════════════════════════════════════════════

    [Fact]
    public async Task Disabled_NoRequestIsLimited()
    {
        await using AegisTestHost host = await StartAsync(perIp: 1, perEmail: 1, enabled: false);

        for (var i = 0; i < 5; i++)
        {
            HttpResponseMessage response = await SignInAsync(host, BadCredential);
            Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        }
    }

    [Theory]
    [InlineData(0, 5, "MaxAttemptsPerIpPerMinute must be greater than 0")]
    [InlineData(10, 0, "MaxAttemptsPerEmailPer15Minutes must be greater than 0")]
    public async Task Startup_NonPositiveLimits_FailValidation(int perIp, int perEmail, string expectedError)
    {
        var ex = await Assert.ThrowsAnyAsync<Exception>(() => StartAsync(perIp, perEmail));

        Assert.Contains(expectedError, ex.Message);
    }

    [Fact]
    public async Task Startup_NonPositiveLimitsWhileDisabled_Starts()
    {
        await using AegisTestHost host = await StartAsync(perIp: 0, perEmail: 0, enabled: false);

        HttpResponseMessage response = await host.Client.PostAsJsonAsync("/api/auth/sign-in/email", new { email = Email, password = GoodCredential });

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }
}
