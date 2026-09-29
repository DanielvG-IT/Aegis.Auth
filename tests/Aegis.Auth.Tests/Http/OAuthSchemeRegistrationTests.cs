using System.Net;

using Aegis.Auth.Constants;

using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.DependencyInjection;

namespace Aegis.Auth.Tests.Http;

public sealed class OAuthSchemeRegistrationTests
{
    [Fact]
    public async Task NoOAuthProvidersConfigured_RequestsDoNotFail()
    {
        await using AegisTestHost host = await AegisTestHost.StartAsync();

        // Any request runs the authentication middleware, which used to build a handler
        // for every OAuth scheme and throw on the empty ClientId of unconfigured providers.
        HttpResponseMessage response = await host.Client.PostAsync("/api/auth/sign-out", null);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    [Fact]
    public async Task OnlyEnabledProvidersHaveSchemes()
    {
        await using AegisTestHost host = await AegisTestHost.StartAsync(o =>
            o.OAuth.AddGoogle("google-client-id", "google-client-secret"));

        IAuthenticationSchemeProvider schemes = host.Services.GetRequiredService<IAuthenticationSchemeProvider>();

        Assert.NotNull(await schemes.GetSchemeAsync(AegisAuthSchemes.Google));
        Assert.Null(await schemes.GetSchemeAsync(AegisAuthSchemes.GitHub));
        Assert.Null(await schemes.GetSchemeAsync(AegisAuthSchemes.Microsoft));
        Assert.Null(await schemes.GetSchemeAsync(AegisAuthSchemes.Apple));
        Assert.NotNull(await schemes.GetSchemeAsync(AegisDefaults.AuthenticationScheme));
    }

    [Fact]
    public async Task OAuthGloballyDisabled_RemovesAllProviderSchemes()
    {
        await using AegisTestHost host = await AegisTestHost.StartAsync(o =>
        {
            o.OAuth.AddGoogle("google-client-id", "google-client-secret");
            o.OAuth.Enabled = false;
        });

        IAuthenticationSchemeProvider schemes = host.Services.GetRequiredService<IAuthenticationSchemeProvider>();

        Assert.Null(await schemes.GetSchemeAsync(AegisAuthSchemes.Google));
    }
}
