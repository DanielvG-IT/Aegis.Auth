using System.Security.Claims;

using Aegis.Auth.Features.OAuth;
using Aegis.Auth.Constants;
using Aegis.Auth.Options;

using Microsoft.AspNetCore.Authentication;

namespace Aegis.Auth.Tests.Features;

public sealed class OAuthProviderCatalogTests
{
    [Fact]
    public void HasEnabledProviders_WhenNoProvidersEnabled_ReturnsFalse()
    {
        var options = new OAuthOptions();

        Assert.False(OAuthProviderCatalog.HasEnabledProviders(options));
    }

    [Fact]
    public void HasEnabledProviders_WhenGitHubEnabled_ReturnsTrue()
    {
        var options = new OAuthOptions();
        options.GitHub.Enabled = true;

        Assert.True(OAuthProviderCatalog.HasEnabledProviders(options));
    }

    [Fact]
    public void BuildIdentity_WhenGitHubClaimsArePresent_UsesMappedClaimsAndTokens()
    {
        Assert.True(OAuthProviderCatalog.TryGet(AegisAuthProviders.GitHub, out OAuthProviderDefinition? provider));

        var principal = new ClaimsPrincipal(new ClaimsIdentity(
        [
            new Claim(ClaimTypes.NameIdentifier, "github-user-42"),
            new Claim(ClaimTypes.Email, "octo@example.com"),
            new Claim("urn:github:email_verified", bool.TrueString),
            new Claim("urn:github:login", "octocat"),
            new Claim("urn:github:avatar_url", "https://example.com/octo.png"),
            new Claim("urn:aegis:id_token", "id-token"),
        ]));

        var properties = new AuthenticationProperties();
        properties.StoreTokens(
        [
            new AuthenticationToken { Name = "access_token", Value = "access-token" },
            new AuthenticationToken { Name = "refresh_token", Value = "refresh-token" },
            new AuthenticationToken { Name = "scope", Value = "read:user user:email" },
            new AuthenticationToken { Name = "expires_at", Value = DateTime.UtcNow.AddMinutes(30).ToString("O") },
        ]);

        ExternalIdentity identity = provider!.BuildIdentity(principal, properties);

        Assert.Equal(AegisAuthProviders.GitHub, identity.ProviderId);
        Assert.Equal("github-user-42", identity.ProviderAccountId);
        Assert.Equal("octo@example.com", identity.Email);
        Assert.True(identity.EmailVerified);
        Assert.Equal("octocat", identity.Name);
        Assert.Equal("https://example.com/octo.png", identity.Image);
        Assert.Equal("access-token", identity.AccessToken);
        Assert.Equal("refresh-token", identity.RefreshToken);
        Assert.Equal("read:user user:email", identity.Scope);
        Assert.Equal("id-token", identity.IdToken);
        Assert.NotNull(identity.AccessTokenExpiresAt);
    }
}
