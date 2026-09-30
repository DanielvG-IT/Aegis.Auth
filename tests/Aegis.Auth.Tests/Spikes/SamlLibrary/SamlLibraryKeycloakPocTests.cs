// ─────────────────────────────────────────────────────────────────────────────
// SPIKE / PROOF OF CONCEPT for #106 (SAML library choice). Throwaway test code.
// See docs/adr/0001-saml-library.md. Remove or replace when the SAML SP (#107) lands.
// ─────────────────────────────────────────────────────────────────────────────

using System.Net;
using System.Security.Claims;
using System.Text.RegularExpressions;

using ITfoxtec.Identity.Saml2.Claims;
using ITfoxtec.Identity.Saml2.Cryptography;
using ITfoxtec.Identity.Saml2.Schemas;
using ITfoxtec.Identity.Saml2.Schemas.Metadata;

using Testcontainers.Keycloak;

namespace Aegis.Auth.Tests.Spikes.SamlLibrary;

/// <summary>
/// End-to-end PoC against a real IdP: Keycloak in a container. The SP connection (IdP entity ID, SSO URL and
/// signing certificates) is built at runtime from Keycloak's metadata, then an SP-initiated login is driven
/// over HTTP and Keycloak's signed response is validated with per-request configuration only.
/// </summary>
[Trait("Category", "Spike")]
public sealed partial class SamlLibraryKeycloakPocTests
{
    private const string Realm = "aegis-saml-poc";
    private const string SpEntityId = "https://sp.aegis.test/saml/tenant-kc";
    private static readonly Uri AcsUrl = new("https://sp.aegis.test/saml/tenant-kc/acs");

    [DockerFact]
    public async Task KeycloakSignedResponse_ValidatesWithPerRequestConfiguration()
    {
        await using KeycloakContainer keycloak = new KeycloakBuilder("keycloak/keycloak:26.3.3")
            .WithRealm(Path.Combine(AppContext.BaseDirectory, "Spikes", "SamlLibrary", "aegis-saml-poc-realm.json"))
            .Build();
        await keycloak.StartAsync();

        var realmUrl = new Uri(new Uri(keycloak.GetBaseAddress()), $"realms/{Realm}/");

        // The container is local, so no proxy. Keycloak marks its login cookies Secure, which CookieContainer
        // will not replay over plain http, so SendAsync forwards them by hand.
        using var http = new HttpClient(new HttpClientHandler { UseCookies = false, AllowAutoRedirect = false, UseProxy = false });

        // 1. Tenant connection, built at runtime from IdP metadata (what an admin would import).
        string metadataXml = await http.GetStringAsync(new Uri(realmUrl, "protocol/saml/descriptor"));
        EntityDescriptor metadata = new EntityDescriptor().ReadIdPSsoDescriptor(metadataXml);
        var connection = new SamlConnection(
            SpEntityId,
            AcsUrl,
            metadata.EntityId,
            metadata.IdPSsoDescriptor.SingleSignOnServices.First(s => s.Binding == ProtocolBindings.HttpRedirect).Location,
            [.. metadata.IdPSsoDescriptor.SigningCertificates]);

        // 2. SP-initiated AuthnRequest over HTTP-Redirect; Keycloak answers with its login form.
        PendingAuthnRequest pending = SamlPocServiceProvider.CreateAuthnRequest(connection, relayState: "state-kc");
        var cookies = new Dictionary<string, string>();
        string loginPage = await SendAsync(http, cookies, new HttpRequestMessage(HttpMethod.Get, pending.RedirectUrl));
        Uri loginAction = new(WebUtility.HtmlDecode(LoginFormAction().Match(loginPage).Groups[1].Value));

        // 3. The user signs in; Keycloak returns the auto-submitting HTTP-POST form for our ACS.
        string postForm = await SendAsync(http, cookies, new HttpRequestMessage(HttpMethod.Post, loginAction)
        {
            Content = new FormUrlEncodedContent(new Dictionary<string, string> { ["username"] = "alice", ["password"] = "alice-password" }),
        });
        Match samlResponse = SamlResponseInput().Match(postForm);
        Assert.True(samlResponse.Success, "Keycloak did not return a SAMLResponse form:\n" + postForm);

        // 4. ACS: validate with configuration derived from the connection for this request only.
        ClaimsIdentity identity = SamlPocServiceProvider.ValidateResponse(connection, pending, WebUtility.HtmlDecode(samlResponse.Groups[1].Value));

        Assert.Equal("alice@example.test", identity.FindFirst(Saml2ClaimTypes.NameId)?.Value);

        // 5. The same response is rejected for a connection that pins a different certificate.
        using var other = new TestSamlIdp("https://other-idp.example.test/saml");
        SamlConnection wrongCert = connection with { IdpSigningCertificates = [other.PublicCertificate] };
        Assert.Throws<InvalidSignatureException>(() => SamlPocServiceProvider.ValidateResponse(wrongCert, pending, WebUtility.HtmlDecode(samlResponse.Groups[1].Value)));
    }

    /// <summary>Sends with the collected cookies and follows redirects, collecting new cookies on the way.</summary>
    private static async Task<string> SendAsync(HttpClient http, Dictionary<string, string> cookies, HttpRequestMessage request)
    {
        for (var hops = 0; hops < 10; hops++)
        {
            if (cookies.Count > 0)
            {
                request.Headers.Add("Cookie", string.Join("; ", cookies.Select(c => $"{c.Key}={c.Value}")));
            }

            using HttpResponseMessage response = await http.SendAsync(request);
            request.Dispose();
            if (response.Headers.TryGetValues("Set-Cookie", out IEnumerable<string>? setCookies))
            {
                foreach (string pair in setCookies.Select(c => c.Split(';')[0]))
                {
                    int eq = pair.IndexOf('=');
                    cookies[pair[..eq]] = pair[(eq + 1)..];
                }
            }

            if ((int)response.StatusCode is >= 300 and < 400 && response.Headers.Location is { } location)
            {
                request = new HttpRequestMessage(HttpMethod.Get, new Uri(response.RequestMessage!.RequestUri!, location));
                continue;
            }

            Assert.True(response.IsSuccessStatusCode, $"Keycloak returned {(int)response.StatusCode}.");
            return await response.Content.ReadAsStringAsync();
        }

        throw new InvalidOperationException("Too many redirects.");
    }

    [GeneratedRegex("<form[^>]+id=\"kc-form-login\"[^>]+action=\"([^\"]+)\"", RegexOptions.IgnoreCase)]
    private static partial Regex LoginFormAction();

    [GeneratedRegex("<input[^>]+name=\"SAMLResponse\"[^>]+value=\"([^\"]+)\"", RegexOptions.IgnoreCase)]
    private static partial Regex SamlResponseInput();
}

/// <summary>
/// Runs only where a Linux Docker engine is reachable (the Windows CI runner cannot run the Keycloak image).
/// </summary>
internal sealed class DockerFactAttribute : FactAttribute
{
    public DockerFactAttribute()
    {
        bool dockerAvailable = OperatingSystem.IsLinux()
            && (Environment.GetEnvironmentVariable("DOCKER_HOST") is not null || File.Exists("/var/run/docker.sock"));

        if (!dockerAvailable)
        {
            Skip = "Requires a Linux Docker engine (Testcontainers + Keycloak).";
        }
    }
}
