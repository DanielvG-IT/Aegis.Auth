using System.Buffers.Text;
using System.Net;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

using Aegis.Auth.Entities;

using Microsoft.AspNetCore.WebUtilities;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.JsonWebTokens;

using OpenIddict.EntityFrameworkCore.Models;

using static Aegis.Auth.Tests.Http.OidcProvider.OidcSpikeEnvironment;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace Aegis.Auth.Tests.Http.OidcProvider;

/// <summary>
/// Proof of concept for #116 (see docs/adr/0002-oidc-provider-engine.md): OpenIddict as the
/// authorization-server engine, with Aegis sessions deciding who is signed in.
/// </summary>
public sealed class OpenIddictSpikeTests
{
    private const string Password = "CorrectPass123!";

    [Fact]
    public async Task RelyingParty_SignsIn_ThroughOpenIddict_BackedByAnAegisSession()
    {
        await using OidcSpikeEnvironment env = await StartAsync();
        var protectedPage = new Uri(RpBase, "/me");

        // No Aegis session: the RP challenges, OpenIddict validates the request, and the
        // passthrough authorize endpoint sends the user to the app's login page.
        HttpResponseMessage toLogin = await env.Browser.GetAsync(protectedPage, stopAt: IsLoginPage);
        Assert.Equal(HttpStatusCode.Redirect, toLogin.StatusCode);
        Uri login = new(IdpBase, toLogin.Headers.Location!);
        Assert.Equal(LoginPath, login.AbsolutePath);
        var returnUrl = QueryHelpers.ParseQuery(login.Query)["returnUrl"].ToString();
        Assert.StartsWith("/oauth2/authorize?", returnUrl);

        // The login page signs the user in with Aegis, then returns to the authorize request,
        // which now issues a code; the RP redeems it and calls userinfo over the backchannel.
        var userId = await SignUpAsync(env, "ada@test.com", "Ada");
        HttpResponseMessage page = await env.Browser.GetAsync(new Uri(IdpBase, returnUrl));

        Assert.Equal(HttpStatusCode.OK, page.StatusCode);
        Assert.Equal(RpBase.Authority, page.RequestMessage!.RequestUri!.Authority);
        JsonElement me = await page.Content.ReadFromJsonAsync<JsonElement>();
        Assert.Equal(userId, me.GetProperty("sub").GetString());
        Assert.Equal("ada@test.com", me.GetProperty("email").GetString());
        Assert.Equal("Ada", me.GetProperty("name").GetString());
        Assert.False(string.IsNullOrEmpty(me.GetProperty("idToken").GetString()));
        Assert.False(string.IsNullOrEmpty(me.GetProperty("refreshToken").GetString()));

        JsonWebToken accessToken = new(me.GetProperty("accessToken").GetString());
        Assert.Equal([McpResource], accessToken.Audiences);
    }

    [Fact]
    public async Task AccessToken_IsAudienceBound_ToTheRequestedResource()
    {
        await using OidcSpikeEnvironment env = await StartAsync();
        var userId = await SignUpAsync(env, "grace@test.com", "Grace");

        JsonElement bound = await SignInWithCodeAsync(env, resource: McpResource);
        JsonElement unbound = await SignInWithCodeAsync(env, resource: null);

        JsonWebToken token = new(bound.GetProperty("access_token").GetString());
        Assert.Equal("at+jwt", token.Typ);
        Assert.Equal(IdpBase.AbsoluteUri, token.Issuer);
        Assert.Equal([McpResource], token.Audiences);
        Assert.Equal(userId, token.Subject);
        Assert.Equal(ClientId, token.GetClaim(Claims.ClientId).Value);

        Assert.Empty(new JsonWebToken(unbound.GetProperty("access_token").GetString()).Audiences);
    }

    [Theory]
    [InlineData(OtherResource, Errors.InvalidRequest)]           // registered, but not permitted for this client
    [InlineData("https://unknown.test/mcp", Errors.InvalidTarget)]
    [InlineData("https://mcp.test/mcp#fragment", Errors.InvalidRequest)]
    [InlineData("not-a-uri", Errors.InvalidRequest)]
    public async Task InvalidResource_IsRejected_BeforeThePassthroughEndpointRuns(string resource, string expectedError)
    {
        await using OidcSpikeEnvironment env = await StartAsync();

        // No Aegis session: had the passthrough endpoint run, it would redirect to the login page,
        // which AuthorizeAsync treats as a failure.
        Dictionary<string, string?> callback = await AuthorizeAsync(env, Pkce().Challenge, resource);

        Assert.Equal(expectedError, callback[Parameters.Error]);
        Assert.False(callback.ContainsKey(Parameters.Code));
    }

    // Gap for #118: OpenIddict compares requested resources ordinally against Uri.AbsoluteUri,
    // which appends "/" to an empty path, while resource permissions are stored as written.
    // A bare-origin resource registered the way MCP recommends (no trailing slash) can't be
    // requested in either form: without the slash it isn't a registered resource, with it the
    // client lacks the permission. Aegis must canonicalise resource URIs in one place.
    [Theory]
    [InlineData(BareOriginResource, Errors.InvalidTarget)]
    [InlineData(BareOriginResource + "/", Errors.InvalidRequest)]
    public async Task BareOriginResource_IsRejected_WithOrWithoutTrailingSlash(string resource, string expectedError)
    {
        await using OidcSpikeEnvironment env = await StartAsync();
        await SignUpAsync(env, "mallory@test.com", "Mallory");

        Dictionary<string, string?> callback = await AuthorizeAsync(env, Pkce().Challenge, resource);

        Assert.Equal(expectedError, callback[Parameters.Error]);
        Assert.False(callback.ContainsKey(Parameters.Code));
    }

    // Gap for #118: RFC 8707 §2.2 lets the token request narrow the audience to one of the
    // granted resources, and says a resource outside the grant is invalid_target. OpenIddict
    // validates the parameter (registered, permitted) but then issues the token for the resources
    // captured at authorize time, whatever the token request asked for.
    [Fact]
    public async Task TokenRequestResource_NeitherNarrowsNorRejects_TheGrantedAudience()
    {
        await using OidcSpikeEnvironment env = await StartAsync();
        await SignUpAsync(env, "narrow@test.com", "Narrow");

        (var verifier, var challenge) = Pkce();
        Dictionary<string, string?> callback = await AuthorizeAsync(env, challenge, McpResource);
        (HttpStatusCode status, JsonElement body) = await TokenAsync(env, new()
        {
            [Parameters.GrantType] = GrantTypes.AuthorizationCode,
            [Parameters.Code] = callback[Parameters.Code],
            [Parameters.RedirectUri] = RedirectUri.AbsoluteUri,
            [Parameters.CodeVerifier] = verifier,
            [Parameters.Resource] = SecondMcpResource,
        });

        Assert.Equal(HttpStatusCode.OK, status);
        Assert.Equal([McpResource], new JsonWebToken(body.GetProperty(Parameters.AccessToken).GetString()).Audiences);
    }

    [Theory]
    [InlineData("/.well-known/openid-configuration")]
    [InlineData("/.well-known/oauth-authorization-server")]
    public async Task Discovery_ServesPkceAndCustomMetadata_AtBothWellKnownPaths(string path)
    {
        await using OidcSpikeEnvironment env = await StartAsync();

        JsonElement metadata = await env.Idp.Client.GetFromJsonAsync<JsonElement>(path);

        Assert.Equal(IdpBase.AbsoluteUri, metadata.GetProperty(Metadata.Issuer).GetString());
        Assert.Contains(CodeChallengeMethods.Sha256, metadata.GetProperty(Metadata.CodeChallengeMethodsSupported).EnumerateArray().Select(e => e.GetString()));
        Assert.True(metadata.GetProperty(ClientIdMetadataDocumentSupported).GetBoolean());
    }

    [Fact]
    public async Task AuthorizationRequest_WithoutPkce_IsRejected()
    {
        await using OidcSpikeEnvironment env = await StartAsync();
        await SignUpAsync(env, "pkce@test.com", "Pkce");

        Dictionary<string, string?> callback = await AuthorizeAsync(env, codeChallenge: null, McpResource);

        Assert.Equal(Errors.InvalidRequest, callback[Parameters.Error]);
        Assert.False(callback.ContainsKey(Parameters.Code));
    }

    [Fact]
    public async Task CodeRedemption_WithTheWrongVerifier_IsRejected()
    {
        await using OidcSpikeEnvironment env = await StartAsync();
        await SignUpAsync(env, "verifier@test.com", "Verifier");

        Dictionary<string, string?> callback = await AuthorizeAsync(env, Pkce().Challenge, McpResource);
        (HttpStatusCode status, JsonElement body) = await TokenAsync(env, new()
        {
            [Parameters.GrantType] = GrantTypes.AuthorizationCode,
            [Parameters.Code] = callback[Parameters.Code],
            [Parameters.RedirectUri] = RedirectUri.AbsoluteUri,
            [Parameters.CodeVerifier] = Pkce().Verifier,
        });

        Assert.Equal(HttpStatusCode.BadRequest, status);
        Assert.Equal(Errors.InvalidGrant, body.GetProperty(Parameters.Error).GetString());
    }

    [Fact]
    public async Task UnregisteredRedirectUri_IsNeverRedirectedTo()
    {
        await using OidcSpikeEnvironment env = await StartAsync();
        await SignUpAsync(env, "redirect@test.com", "Redirect");

        HttpResponseMessage response = await env.Browser.GetAsync(
            AuthorizeUri(Pkce().Challenge, McpResource, redirectUri: "https://evil.test/callback"));

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Null(response.Headers.Location);
    }

    [Fact]
    public async Task AuthorizationCode_Replay_IsRejected_AndRevokesTheTokensItIssued()
    {
        await using OidcSpikeEnvironment env = await StartAsync();
        await SignUpAsync(env, "replay@test.com", "Replay");

        (var verifier, var challenge) = Pkce();
        Dictionary<string, string?> callback = await AuthorizeAsync(env, challenge, McpResource);
        var redeem = new Dictionary<string, string?>
        {
            [Parameters.GrantType] = GrantTypes.AuthorizationCode,
            [Parameters.Code] = callback[Parameters.Code],
            [Parameters.RedirectUri] = RedirectUri.AbsoluteUri,
            [Parameters.CodeVerifier] = verifier,
        };

        (HttpStatusCode first, JsonElement tokens) = await TokenAsync(env, redeem);
        (HttpStatusCode replay, JsonElement replayBody) = await TokenAsync(env, redeem);
        (HttpStatusCode refresh, _) = await RefreshAsync(env, tokens.GetProperty(Parameters.RefreshToken).GetString());

        Assert.Equal(HttpStatusCode.OK, first);
        Assert.Equal(HttpStatusCode.BadRequest, replay);
        Assert.Equal(Errors.InvalidGrant, replayBody.GetProperty(Parameters.Error).GetString());
        Assert.Equal(HttpStatusCode.BadRequest, refresh);
    }

    [Fact]
    public async Task RefreshToken_Reuse_RevokesTheTokenFamily()
    {
        await using OidcSpikeEnvironment env = await StartAsync();
        await SignUpAsync(env, "rotate@test.com", "Rotate");
        JsonElement tokens = await SignInWithCodeAsync(env, McpResource);
        var original = tokens.GetProperty(Parameters.RefreshToken).GetString();

        (HttpStatusCode rotated, JsonElement rotatedBody) = await RefreshAsync(env, original);
        (HttpStatusCode reuse, _) = await RefreshAsync(env, original);
        (HttpStatusCode afterReuse, _) = await RefreshAsync(env, rotatedBody.GetProperty(Parameters.RefreshToken).GetString());

        Assert.Equal(HttpStatusCode.OK, rotated);
        Assert.Equal([McpResource], new JsonWebToken(rotatedBody.GetProperty(Parameters.AccessToken).GetString()).Audiences);
        Assert.Equal(HttpStatusCode.BadRequest, reuse);
        Assert.Equal(HttpStatusCode.BadRequest, afterReuse);
    }

    [Fact]
    public async Task RevokedAegisSession_IsSentToLogin_InsteadOfIssuingACode()
    {
        await using OidcSpikeEnvironment env = await StartAsync();
        await SignUpAsync(env, "revoked@test.com", "Revoked");

        await using (AsyncServiceScope scope = env.Idp.Services.CreateAsyncScope())
        {
            await scope.ServiceProvider.GetRequiredService<OidcSpikeDbContext>().Sessions.ExecuteDeleteAsync();
        }

        HttpResponseMessage response = await env.Browser.GetAsync(AuthorizeUri(Pkce().Challenge, McpResource), stopAt: IsLoginPage);

        Assert.Equal(LoginPath, new Uri(IdpBase, response.Headers.Location!).AbsolutePath);
    }

    [Fact]
    public async Task TamperedAegisSessionCookie_IsSentToLogin_InsteadOfIssuingACode()
    {
        await using OidcSpikeEnvironment env = await StartAsync();
        await SignUpAsync(env, "tamper@test.com", "Tamper");

        Cookie session = env.Browser.Cookies.GetCookies(IdpBase)["aegis.session"]!;
        session.Value = session.Value[..^2] + (session.Value.EndsWith("AA", StringComparison.Ordinal) ? "BB" : "AA");

        HttpResponseMessage response = await env.Browser.GetAsync(AuthorizeUri(Pkce().Challenge, McpResource), stopAt: IsLoginPage);

        Assert.Equal(LoginPath, new Uri(IdpBase, response.Headers.Location!).AbsolutePath);
    }

    [Fact]
    public async Task SharedDbContext_HoldsAegisAndOpenIddictTables_WithoutCollisions()
    {
        await using OidcSpikeEnvironment env = await StartAsync();
        await using AsyncServiceScope scope = env.Idp.Services.CreateAsyncScope();
        OidcSpikeDbContext db = scope.ServiceProvider.GetRequiredService<OidcSpikeDbContext>();

        var tables = db.Model.GetEntityTypes().Select(e => e.GetTableName()).ToList();

        Assert.Equal(tables.Count, tables.Distinct(StringComparer.OrdinalIgnoreCase).Count());
        Assert.Contains("Users", tables);
        Assert.Contains("Sessions", tables);
        Assert.Contains("OpenIddictApplications", tables);
        Assert.Contains("OpenIddictTokens", tables);
        Assert.Equal(1, await db.Set<OpenIddictEntityFrameworkCoreApplication>().CountAsync());
    }

    private static bool IsLoginPage(Uri uri) => uri.Authority == IdpBase.Authority && uri.AbsolutePath == LoginPath;

    private static async Task<string> SignUpAsync(OidcSpikeEnvironment env, string email, string name)
    {
        HttpResponseMessage response = await env.Browser.PostJsonAsync(
            new Uri(IdpBase, "/api/auth/sign-up/email"),
            new { name, email, password = Password });
        response.EnsureSuccessStatusCode();

        await using AsyncServiceScope scope = env.Idp.Services.CreateAsyncScope();
        User user = await scope.ServiceProvider.GetRequiredService<OidcSpikeDbContext>().Users.SingleAsync(u => u.Email == email);
        return user.Id;
    }

    private static (string Verifier, string Challenge) Pkce()
    {
        var verifier = Base64Url.EncodeToString(RandomNumberGenerator.GetBytes(32));
        return (verifier, Base64Url.EncodeToString(SHA256.HashData(Encoding.ASCII.GetBytes(verifier))));
    }

    private static Uri AuthorizeUri(string? codeChallenge, string? resource, string? redirectUri = null)
    {
        var query = new Dictionary<string, string?>
        {
            [Parameters.ClientId] = ClientId,
            [Parameters.RedirectUri] = redirectUri ?? RedirectUri.AbsoluteUri,
            [Parameters.ResponseType] = ResponseTypes.Code,
            [Parameters.Scope] = $"{Scopes.OpenId} {Scopes.Email} {Scopes.OfflineAccess}",
            [Parameters.State] = Guid.NewGuid().ToString("N"),
        };
        if (codeChallenge is not null)
        {
            query[Parameters.CodeChallenge] = codeChallenge;
            query[Parameters.CodeChallengeMethod] = CodeChallengeMethods.Sha256;
        }

        if (resource is not null)
        {
            query[Parameters.Resource] = resource;
        }

        return new Uri(QueryHelpers.AddQueryString(new Uri(IdpBase, "/oauth2/authorize").AbsoluteUri, query));
    }

    /// <summary>
    /// Runs an authorization request and returns the response parameters: those sent back to the
    /// client's redirect URI, or those of the error page OpenIddict renders itself when it rejects
    /// the request before the redirect URI has been validated.
    /// </summary>
    private static async Task<Dictionary<string, string?>> AuthorizeAsync(OidcSpikeEnvironment env, string? codeChallenge, string? resource)
    {
        HttpResponseMessage response = await env.Browser.GetAsync(
            AuthorizeUri(codeChallenge, resource),
            stopAt: uri => IsLoginPage(uri) || uri.GetLeftPart(UriPartial.Path) == RedirectUri.AbsoluteUri);

        if (response.StatusCode == HttpStatusCode.BadRequest)
        {
            var body = await response.Content.ReadAsStringAsync();
            return body.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
                .Select(line => line.Split(':', 2))
                .ToDictionary(pair => pair[0], pair => (string?)pair[1]);
        }

        Assert.Equal(HttpStatusCode.Redirect, response.StatusCode);
        Uri location = response.Headers.Location!;
        Assert.Equal(RedirectUri.AbsoluteUri, location.GetLeftPart(UriPartial.Path));
        return QueryHelpers.ParseQuery(location.Query).ToDictionary(p => p.Key, p => (string?)p.Value.ToString());
    }

    private static async Task<JsonElement> SignInWithCodeAsync(OidcSpikeEnvironment env, string? resource)
    {
        (var verifier, var challenge) = Pkce();
        Dictionary<string, string?> callback = await AuthorizeAsync(env, challenge, resource);
        (HttpStatusCode status, JsonElement body) = await TokenAsync(env, new()
        {
            [Parameters.GrantType] = GrantTypes.AuthorizationCode,
            [Parameters.Code] = callback[Parameters.Code],
            [Parameters.RedirectUri] = RedirectUri.AbsoluteUri,
            [Parameters.CodeVerifier] = verifier,
        });

        Assert.Equal(HttpStatusCode.OK, status);
        return body;
    }

    private static Task<(HttpStatusCode, JsonElement)> RefreshAsync(OidcSpikeEnvironment env, string? refreshToken)
        => TokenAsync(env, new()
        {
            [Parameters.GrantType] = GrantTypes.RefreshToken,
            [Parameters.RefreshToken] = refreshToken,
        });

    private static async Task<(HttpStatusCode, JsonElement)> TokenAsync(OidcSpikeEnvironment env, Dictionary<string, string?> form)
    {
        form[Parameters.ClientId] = ClientId;
        form[Parameters.ClientSecret] = ClientSecret;

        using var content = new FormUrlEncodedContent(form);
        HttpResponseMessage response = await env.Idp.Client.PostAsync("/oauth2/token", content);
        return (response.StatusCode, await response.Content.ReadFromJsonAsync<JsonElement>());
    }
}
