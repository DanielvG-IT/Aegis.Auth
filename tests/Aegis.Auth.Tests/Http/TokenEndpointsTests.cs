using System.Net;
using System.Net.Http.Json;

using Aegis.Auth.Options;

using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;

namespace Aegis.Auth.Tests.Http;

/// <summary>
/// End-to-end checks for the password reset and email verification endpoints:
/// raw tokens must only ever reach the delivery delegate, never an HTTP response.
/// </summary>
public sealed class TokenEndpointsTests
{
    private const string Email = "flow@test.com";
    private const string Password = "OriginalPass123!";

    private static async Task SignUpAsync(HttpClient client)
    {
        HttpResponseMessage response = await client.PostAsJsonAsync("/api/auth/sign-up/email", new { name = "Flow", email = Email, password = Password });
        Assert.True(response.IsSuccessStatusCode, await response.Content.ReadAsStringAsync());
    }

    private static IReadOnlyList<string> RoutePatterns(AegisTestHost host) =>
        [.. host.Services.GetRequiredService<EndpointDataSource>().Endpoints
            .OfType<RouteEndpoint>()
            .Select(e => e.RoutePattern.RawText ?? string.Empty)];

    [Fact]
    public async Task PasswordReset_FullFlow_TokenNeverInResponse()
    {
        var tokens = new List<string>();
        await using AegisTestHost host = await AegisTestHost.StartAsync(o =>
            o.EmailAndPassword.SendResetPassword = (ctx, _) =>
            {
                // Delegates resolve app services (e.g. an email sender) from the request scope.
                Assert.NotNull(ctx.Services.GetService<Aegis.Auth.Abstractions.IAuthDbContext>());
                tokens.Add(ctx.Token);
                return Task.CompletedTask;
            });
        await SignUpAsync(host.Client);

        HttpResponseMessage send = await host.Client.PostAsJsonAsync("/api/auth/password-reset/send-token", new { email = Email });
        var sendBody = await send.Content.ReadAsStringAsync();

        Assert.Equal(HttpStatusCode.OK, send.StatusCode);
        var token = Assert.Single(tokens);
        Assert.DoesNotContain(token, sendBody);
        Assert.DoesNotContain(token, string.Join(";", send.Headers.SelectMany(h => h.Value)));

        // No session cookie is sent: the token alone must be enough.
        HttpResponseMessage reset = await host.Client.PostAsJsonAsync("/api/auth/password-reset/reset", new { token, newPassword = "BrandNewPass123!" });
        Assert.Equal(HttpStatusCode.OK, reset.StatusCode);

        HttpResponseMessage oldPassword = await host.Client.PostAsJsonAsync("/api/auth/sign-in/email", new { email = Email, password = Password });
        HttpResponseMessage newPassword = await host.Client.PostAsJsonAsync("/api/auth/sign-in/email", new { email = Email, password = "BrandNewPass123!" });
        Assert.Equal(HttpStatusCode.Unauthorized, oldPassword.StatusCode);
        Assert.Equal(HttpStatusCode.OK, newPassword.StatusCode);
    }

    [Fact]
    public async Task PasswordReset_UnknownEmail_ReturnsSameResponseAsKnownEmail()
    {
        await using AegisTestHost host = await AegisTestHost.StartAsync(o =>
            o.EmailAndPassword.SendResetPassword = (_, _) => Task.CompletedTask);
        await SignUpAsync(host.Client);

        HttpResponseMessage known = await host.Client.PostAsJsonAsync("/api/auth/password-reset/send-token", new { email = Email });
        HttpResponseMessage unknown = await host.Client.PostAsJsonAsync("/api/auth/password-reset/send-token", new { email = "ghost@test.com" });

        Assert.Equal(known.StatusCode, unknown.StatusCode);
        Assert.Equal(await known.Content.ReadAsStringAsync(), await unknown.Content.ReadAsStringAsync());
    }

    [Fact]
    public async Task EmailVerification_RequiredFlow_BlocksSignInUntilVerifiedWithoutSession()
    {
        var tokens = new List<string>();
        await using AegisTestHost host = await AegisTestHost.StartAsync(o =>
        {
            o.EmailAndPassword.RequireEmailVerification = true;
            o.EmailVerification.SendVerificationEmail = (ctx, _) =>
            {
                tokens.Add(ctx.Token);
                return Task.CompletedTask;
            };
        });

        HttpResponseMessage signUp = await host.Client.PostAsJsonAsync("/api/auth/sign-up/email", new { name = "Flow", email = Email, password = Password });
        var signUpToken = Assert.Single(tokens);
        Assert.DoesNotContain(signUpToken, await signUp.Content.ReadAsStringAsync());
        Assert.False(signUp.Headers.Contains("Set-Cookie"), "Sign-up must not auto sign in while verification is required");

        HttpResponseMessage blocked = await host.Client.PostAsJsonAsync("/api/auth/sign-in/email", new { email = Email, password = Password });
        Assert.Equal(HttpStatusCode.Forbidden, blocked.StatusCode);

        // Sign-in re-sent a fresh link, which supersedes the one from sign-up.
        Assert.Equal(2, tokens.Count);
        Assert.DoesNotContain(tokens[1], await blocked.Content.ReadAsStringAsync());

        HttpResponseMessage resend = await host.Client.PostAsJsonAsync("/api/auth/email-verify/send-token", new { email = Email });
        Assert.Equal(HttpStatusCode.OK, resend.StatusCode);
        Assert.DoesNotContain(tokens[^1], await resend.Content.ReadAsStringAsync());

        HttpResponseMessage verify = await host.Client.PostAsJsonAsync("/api/auth/email-verify/verify", new { token = tokens[^1] });
        Assert.Equal(HttpStatusCode.OK, verify.StatusCode);

        HttpResponseMessage signIn = await host.Client.PostAsJsonAsync("/api/auth/sign-in/email", new { email = Email, password = Password });
        Assert.Equal(HttpStatusCode.OK, signIn.StatusCode);
    }

    [Fact]
    public async Task TokenEndpoints_NotMappedWithoutDeliveryDelegates()
    {
        await using AegisTestHost host = await AegisTestHost.StartAsync();

        IReadOnlyList<string> routes = RoutePatterns(host);

        Assert.DoesNotContain(routes, r => r.Contains("password-reset"));
        Assert.DoesNotContain(routes, r => r.Contains("email-verify"));
    }

    [Fact]
    public async Task TokenEndpoints_MappedUnderBasePathWhenDelegatesConfigured()
    {
        await using AegisTestHost host = await AegisTestHost.StartAsync(o =>
        {
            o.EmailAndPassword.SendResetPassword = (_, _) => Task.CompletedTask;
            o.EmailVerification.SendVerificationEmail = (_, _) => Task.CompletedTask;
        });

        IReadOnlyList<string> routes = RoutePatterns(host);

        Assert.Contains("/api/auth/password-reset/send-token", routes);
        Assert.Contains("/api/auth/password-reset/reset", routes);
        Assert.Contains("/api/auth/email-verify/send-token", routes);
        Assert.Contains("/api/auth/email-verify/verify", routes);
    }

    [Fact]
    public async Task Startup_RequireVerificationWithoutDelegate_FailsValidation()
    {
        var ex = await Assert.ThrowsAnyAsync<Exception>(() =>
            AegisTestHost.StartAsync(o => o.EmailAndPassword.RequireEmailVerification = true));

        Assert.Contains("SendVerificationEmail must be configured", ex.Message);
    }

    [Fact]
    public async Task Startup_SendOnSignUpWithoutDelegate_FailsValidation()
    {
        var ex = await Assert.ThrowsAnyAsync<Exception>(() =>
            AegisTestHost.StartAsync(o => o.EmailVerification.SendOnSignUp = true));

        Assert.Contains("SendVerificationEmail must be configured", ex.Message);
    }
}
