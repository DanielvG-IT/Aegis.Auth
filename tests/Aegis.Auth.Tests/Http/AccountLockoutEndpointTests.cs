using System.Net;
using System.Net.Http.Json;

namespace Aegis.Auth.Tests.Http;

public sealed class AccountLockoutEndpointTests
{
    [Fact]
    public async Task LockedAccount_ReturnsForbiddenWithAccountLockedCode()
    {
        await using AegisTestHost host = await AegisTestHost.StartAsync(o =>
        {
            o.AccountLockout.Enabled = true;
            o.AccountLockout.MaxFailedAttempts = 2;
        });
        await host.Client.PostAsJsonAsync("/api/auth/sign-up/email", new { name = "Lock", email = "lock@test.com", password = "CorrectPass123!" });

        for (var i = 0; i < 2; i++)
        {
            await host.Client.PostAsJsonAsync("/api/auth/sign-in/email", new { email = "lock@test.com", password = "WrongPass123!" });
        }

        HttpResponseMessage response = await host.Client.PostAsJsonAsync("/api/auth/sign-in/email", new { email = "lock@test.com", password = "CorrectPass123!" });

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        Assert.Contains("ACCOUNT_LOCKED", await response.Content.ReadAsStringAsync());
    }

    [Fact]
    public async Task Startup_InvalidLockoutOptions_FailValidation()
    {
        var ex = await Assert.ThrowsAnyAsync<Exception>(() => AegisTestHost.StartAsync(o =>
        {
            o.AccountLockout.Enabled = true;
            o.AccountLockout.MaxFailedAttempts = 0;
        }));

        Assert.Contains("MaxFailedAttempts must be greater than 0", ex.Message);
    }
}
