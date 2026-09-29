using System.Net;
using System.Net.Http.Json;
using System.Text.Json;

using Aegis.Auth.Options;

namespace Aegis.Auth.Tests.Http;

public sealed class OAuthProvidersEndpointTests
{
    [Fact]
    public async Task ListsOnlyEnabledProviders()
    {
        await using AegisTestHost host = await AegisTestHost.StartAsync(o =>
        {
            ConfigureAllProviders(o.OAuth);
            o.OAuth.GitHub.Enabled = false;
            o.OAuth.Apple.Enabled = false;
        });

        // Also proves "providers" is not routed to /sign-in/oauth/{provider}.
        HttpResponseMessage response = await host.Client.GetAsync("/api/auth/sign-in/oauth/providers");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal(
            [("google", "Google"), ("microsoft", "Microsoft")],
            await ReadProvidersAsync(response));
    }

    [Fact]
    public async Task UsesConfiguredBasePath()
    {
        await using AegisTestHost host = await AegisTestHost.StartAsync(
            o => ConfigureAllProviders(o.OAuth),
            e => e.BasePath = "/auth");

        HttpResponseMessage response = await host.Client.GetAsync("/auth/sign-in/oauth/providers");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal(4, (await ReadProvidersAsync(response)).Count);
    }

    [Fact]
    public async Task OAuthDisabled_NotMappedWhenRespectingConfiguration()
    {
        await using AegisTestHost host = await AegisTestHost.StartAsync(o =>
        {
            ConfigureAllProviders(o.OAuth);
            o.OAuth.Enabled = false;
        });

        HttpResponseMessage response = await host.Client.GetAsync("/api/auth/sign-in/oauth/providers");

        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
    }

    [Fact]
    public async Task OAuthDisabled_ForceMapped_ReturnsEmptyList()
    {
        await using AegisTestHost host = await AegisTestHost.StartAsync(
            o =>
            {
                ConfigureAllProviders(o.OAuth);
                o.OAuth.Enabled = false;
            },
            e => e.RespectConfiguration = false);

        HttpResponseMessage response = await host.Client.GetAsync("/api/auth/sign-in/oauth/providers");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Empty(await ReadProvidersAsync(response));
    }

    // Every provider gets credentials so the auth middleware can build all registered schemes.
    private static void ConfigureAllProviders(OAuthOptions oauth)
    {
        oauth.AddGoogle("google-client-id", "google-client-secret");
        oauth.AddGitHub("github-client-id", "github-client-secret");
        oauth.AddMicrosoft("microsoft-client-id", "microsoft-client-secret");
        oauth.AddApple("apple-client-id", "apple-client-secret");
    }

    private static async Task<List<(string Id, string Name)>> ReadProvidersAsync(HttpResponseMessage response)
    {
        JsonElement body = await response.Content.ReadFromJsonAsync<JsonElement>();
        return [.. body.GetProperty("providers")
            .EnumerateArray()
            .Select(p => (p.GetProperty("id").GetString()!, p.GetProperty("name").GetString()!))];
    }
}
