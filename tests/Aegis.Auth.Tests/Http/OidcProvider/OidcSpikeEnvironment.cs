using System.Security.Claims;
using System.Security.Cryptography;

using Aegis.Auth.Abstractions;
using Aegis.Auth.Constants;
using Aegis.Auth.Entities;

using Microsoft.AspNetCore;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Extensions;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;

using OpenIddict.Abstractions;
using OpenIddict.Server;
using OpenIddict.Server.AspNetCore;

using static OpenIddict.Abstractions.OpenIddictConstants;

namespace Aegis.Auth.Tests.Http.OidcProvider;

/// <summary>
/// Two TestServers for the #116 spike: an identity provider (Aegis + OpenIddict, authorize and
/// userinfo in passthrough mode) and a relying party using the stock ASP.NET
/// <c>AddOpenIdConnect</c> handler, plus a browser that spans both.
/// </summary>
internal sealed class OidcSpikeEnvironment : IAsyncDisposable
{
    public static readonly Uri IdpBase = new("https://idp.test/");
    public static readonly Uri RpBase = new("https://rp.test/");
    public static readonly Uri RedirectUri = new("https://rp.test/signin-oidc");

    public const string ClientId = "spike-rp";
    public const string ClientSecret = "spike-rp-secret-that-is-long-enough";
    public const string LoginPath = "/login";
    public const string ClientIdMetadataDocumentSupported = "client_id_metadata_document_supported";

    /// <summary>Registered on the server and permitted for the client.</summary>
    public const string McpResource = "https://mcp.test/mcp";

    /// <summary>A second resource registered on the server and permitted for the client.</summary>
    public const string SecondMcpResource = "https://mcp2.test/mcp";

    /// <summary>Registered on the server but not permitted for the client.</summary>
    public const string OtherResource = "https://other.test/mcp";

    /// <summary>Registered and permitted exactly as written (no trailing slash), as MCP recommends.</summary>
    public const string BareOriginResource = "https://origin.test";

    // Generated once per test run: RSA key generation dominates start-up when done per host
    // (what AddEphemeralSigningKey does). Production uses certificates; see the ADR.
    private static readonly RsaSecurityKey SigningKey = new(RSA.Create(2048));
    private static readonly SymmetricSecurityKey EncryptionKey = new(RandomNumberGenerator.GetBytes(32));

    private readonly SqliteConnection _connection;
    private readonly WebApplication _rp;

    public AegisTestHost Idp { get; }
    public TestBrowser Browser { get; }

    private OidcSpikeEnvironment(SqliteConnection connection, AegisTestHost idp, WebApplication rp, TestBrowser browser)
    {
        _connection = connection;
        Idp = idp;
        _rp = rp;
        Browser = browser;
    }

    public static async Task<OidcSpikeEnvironment> StartAsync()
    {
        // SQLite rather than EF InMemory: OpenIddict redeems tokens through optimistic
        // concurrency and revokes token chains in bulk, which InMemory doesn't model faithfully.
        var connection = new SqliteConnection("DataSource=:memory:");
        await connection.OpenAsync();

        AegisTestHost idp = await AegisTestHost.StartAsync<OidcSpikeDbContext>(
            db => db.UseSqlite(connection),
            configureServices: ConfigureOpenIddict,
            configureApp: MapPassthroughEndpoints,
            baseAddress: IdpBase);

        await using (AsyncServiceScope scope = idp.Services.CreateAsyncScope())
        {
            await scope.ServiceProvider.GetRequiredService<OidcSpikeDbContext>().Database.EnsureCreatedAsync();
            await scope.ServiceProvider.GetRequiredService<IOpenIddictApplicationManager>().CreateAsync(ClientDescriptor());
        }

        WebApplication rp = await StartRelyingPartyAsync(idp.Server);

        var browser = new TestBrowser();
        browser.AddHost(idp.Server);
        browser.AddHost(rp.GetTestServer());

        return new OidcSpikeEnvironment(connection, idp, rp, browser);
    }

    private static void ConfigureOpenIddict(IServiceCollection services)
    {
        services.AddOpenIddict()
            .AddCore(options => options.UseEntityFrameworkCore().UseDbContext<OidcSpikeDbContext>())
            .AddServer(options =>
            {
                options.SetIssuer(IdpBase);
                options.SetAuthorizationEndpointUris("oauth2/authorize")
                       .SetTokenEndpointUris("oauth2/token")
                       .SetUserInfoEndpointUris("oauth2/userinfo");

                options.AllowAuthorizationCodeFlow()
                       .AllowRefreshTokenFlow()
                       .RequireProofKeyForCodeExchange();

                options.RegisterScopes(Scopes.Email, Scopes.Profile, Scopes.OfflineAccess);
                options.RegisterResources(new Uri(McpResource), new Uri(SecondMcpResource), new Uri(OtherResource), new Uri(BareOriginResource));

                // Resource servers (MCP servers) must be able to read access tokens: sign, don't encrypt.
                options.AddEncryptionKey(EncryptionKey)
                       .AddSigningKey(SigningKey)
                       .DisableAccessTokenEncryption();

                // No reuse leeway, so a replayed refresh token is treated as theft straight away.
                options.SetRefreshTokenReuseLeeway(null);

                // The CIMD issue (#119) advertises support through a custom metadata field.
                options.AddEventHandler<OpenIddictServerEvents.HandleConfigurationRequestContext>(handler =>
                    handler.UseInlineHandler(context =>
                    {
                        context.Metadata[ClientIdMetadataDocumentSupported] = true;
                        return ValueTask.CompletedTask;
                    }));

                options.UseAspNetCore()
                       .EnableAuthorizationEndpointPassthrough()
                       .EnableUserInfoEndpointPassthrough();
            });
    }

    private static OpenIddictApplicationDescriptor ClientDescriptor()
    {
        var descriptor = new OpenIddictApplicationDescriptor
        {
            ClientId = ClientId,
            ClientSecret = ClientSecret,
            ClientType = ClientTypes.Confidential,
            DisplayName = "Spike relying party",
            RedirectUris = { RedirectUri },
            Permissions =
            {
                Permissions.Endpoints.Authorization,
                Permissions.Endpoints.Token,
                Permissions.GrantTypes.AuthorizationCode,
                Permissions.GrantTypes.RefreshToken,
                Permissions.ResponseTypes.Code,
                Permissions.Scopes.Email,
                Permissions.Scopes.Profile,
            },
            Requirements = { Requirements.Features.ProofKeyForCodeExchange },
        };

        return descriptor.AddResourcePermissions(McpResource, SecondMcpResource, BareOriginResource);
    }

    private static void MapPassthroughEndpoints(WebApplication app)
    {
        // OpenIddict has already validated client, redirect URI, PKCE, scopes and resources
        // before this runs; it only decides who the user is.
        app.MapMethods("/oauth2/authorize", [HttpMethods.Get, HttpMethods.Post], async (HttpContext http, IAuthDbContext db) =>
        {
            OpenIddictRequest request = http.GetOpenIddictServerRequest()
                ?? throw new InvalidOperationException("Not an OpenIddict authorization request.");

            AuthenticateResult session = await http.AuthenticateAsync(AegisDefaults.AuthenticationScheme);
            var userId = session.Principal?.FindFirstValue(ClaimTypes.NameIdentifier);
            User? user = userId is null ? null : await db.Users.FindAsync([userId], http.RequestAborted);
            if (user is null)
            {
                // Stands in for the app's login page, which returns here after sign-in.
                return Results.Redirect($"{LoginPath}?returnUrl={Uri.EscapeDataString(http.Request.GetEncodedPathAndQuery())}");
            }

            var identity = new ClaimsIdentity(
                authenticationType: TokenValidationParameters.DefaultAuthenticationType,
                nameType: Claims.Name,
                roleType: Claims.Role);

            identity.SetClaim(Claims.Subject, user.Id)
                    .SetClaim(Claims.Email, user.Email)
                    .SetClaim(Claims.Name, user.Name);

            identity.SetScopes(request.GetScopes());
            identity.SetResources(request.GetResources()); // → the access token's "aud"
            identity.SetDestinations(claim => claim.Type switch
            {
                Claims.Email when identity.HasScope(Scopes.Email) => [Destinations.AccessToken, Destinations.IdentityToken],
                Claims.Name when identity.HasScope(Scopes.Profile) => [Destinations.AccessToken, Destinations.IdentityToken],
                _ => [Destinations.AccessToken],
            });

            return Results.SignIn(new ClaimsPrincipal(identity), properties: null, OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
        });

        // Claims come from the Aegis user store at call time, not from the token.
        app.MapMethods("/oauth2/userinfo", [HttpMethods.Get, HttpMethods.Post], async (HttpContext http, IAuthDbContext db) =>
        {
            AuthenticateResult result = await http.AuthenticateAsync(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
            var subject = result.Principal?.GetClaim(Claims.Subject);
            User? user = subject is null ? null : await db.Users.FindAsync([subject], http.RequestAborted);
            if (result.Principal is null || user is null)
            {
                return Results.Challenge(
                    new AuthenticationProperties(new Dictionary<string, string?>
                    {
                        [OpenIddictServerAspNetCoreConstants.Properties.Error] = Errors.InvalidToken,
                    }),
                    [OpenIddictServerAspNetCoreDefaults.AuthenticationScheme]);
            }

            var claims = new Dictionary<string, object> { [Claims.Subject] = user.Id };
            if (result.Principal.HasScope(Scopes.Email))
            {
                claims[Claims.Email] = user.Email;
                claims[Claims.EmailVerified] = user.EmailVerified;
            }

            if (result.Principal.HasScope(Scopes.Profile) && user.Name is not null)
            {
                claims[Claims.Name] = user.Name;
            }

            return Results.Ok(claims);
        });
    }

    private static async Task<WebApplication> StartRelyingPartyAsync(TestServer idpServer)
    {
        WebApplicationBuilder builder = WebApplication.CreateBuilder(new WebApplicationOptions
        {
            EnvironmentName = Environments.Development,
        });
        builder.WebHost.UseTestServer(o => o.BaseAddress = RpBase);

        builder.Services
            .AddAuthentication(o =>
            {
                o.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
                o.DefaultChallengeScheme = OpenIdConnectDefaults.AuthenticationScheme;
            })
            .AddCookie()
            .AddOpenIdConnect(o =>
            {
                o.Authority = IdpBase.AbsoluteUri;
                o.BackchannelHttpHandler = idpServer.CreateHandler();
                o.ClientId = ClientId;
                o.ClientSecret = ClientSecret;
                o.ResponseType = OpenIdConnectResponseType.Code;
                o.ResponseMode = OpenIdConnectResponseMode.Query;
                o.UsePkce = true;
                o.Scope.Add(Scopes.Email);
                o.Scope.Add(Scopes.OfflineAccess);
                o.Resource = McpResource;
                o.SaveTokens = true;
                o.GetClaimsFromUserInfoEndpoint = true;
                o.MapInboundClaims = false;
            });
        builder.Services.AddAuthorization();

        WebApplication app = builder.Build();
        app.UseAuthentication();
        app.UseAuthorization();
        // Two parameters on purpose: "async (HttpContext) => ..." binds to the RequestDelegate
        // overload and silently discards the result.
        app.MapGet("/me", async (HttpContext http, ClaimsPrincipal user) => Results.Ok(new
        {
            sub = user.FindFirstValue(Claims.Subject),
            email = user.FindFirstValue(Claims.Email),
            name = user.FindFirstValue(Claims.Name),
            accessToken = await http.GetTokenAsync("access_token"),
            refreshToken = await http.GetTokenAsync("refresh_token"),
            idToken = await http.GetTokenAsync("id_token"),
        })).RequireAuthorization();

        await app.StartAsync();
        return app;
    }

    public async ValueTask DisposeAsync()
    {
        Browser.Dispose();
        await _rp.StopAsync();
        await _rp.DisposeAsync();
        await Idp.DisposeAsync();
        await _connection.DisposeAsync();
    }
}
