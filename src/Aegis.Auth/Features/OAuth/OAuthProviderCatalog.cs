using System.Globalization;
using System.Security.Claims;

using Aegis.Auth.Constants;
using Aegis.Auth.Options;

using Microsoft.AspNetCore.Authentication;

namespace Aegis.Auth.Features.OAuth;

internal static class OAuthProviderCatalog
{
    private static readonly OAuthProviderDefinition[] Providers =
    [
        new(
            AegisAuthProviders.Google,
            "Google",
            AegisAuthSchemes.Google,
            nameof(OAuthOptions.Google),
            options => options.Google,
            BuildGoogleIdentity),
        new(
            AegisAuthProviders.GitHub,
            "GitHub",
            AegisAuthSchemes.GitHub,
            nameof(OAuthOptions.GitHub),
            options => options.GitHub,
            BuildGitHubIdentity),
        new(
            AegisAuthProviders.Microsoft,
            "Microsoft",
            AegisAuthSchemes.Microsoft,
            nameof(OAuthOptions.Microsoft),
            options => options.Microsoft,
            BuildMicrosoftIdentity),
        new(
            AegisAuthProviders.Apple,
            "Apple",
            AegisAuthSchemes.Apple,
            nameof(OAuthOptions.Apple),
            options => options.Apple,
            BuildAppleIdentity),
    ];

    private static readonly IReadOnlyDictionary<string, OAuthProviderDefinition> ProviderMap =
        Providers.ToDictionary(provider => provider.ProviderId, StringComparer.OrdinalIgnoreCase);

    public static IReadOnlyList<OAuthProviderDefinition> All => Providers;

    public static bool TryGet(string? providerId, out OAuthProviderDefinition? provider)
    {
        if (string.IsNullOrWhiteSpace(providerId))
        {
            provider = null;
            return false;
        }

        return ProviderMap.TryGetValue(providerId, out provider);
    }

    public static bool HasEnabledProviders(OAuthOptions options) =>
        Providers.Any(provider => provider.GetOptions(options).Enabled);

    private static ExternalIdentity BuildGoogleIdentity(ClaimsPrincipal principal, AuthenticationProperties? properties) =>
        BuildIdentity(
            AegisAuthProviders.Google,
            principal,
            properties,
            accountIdClaimTypes: [ClaimTypes.NameIdentifier, "sub"],
            emailClaimTypes: [ClaimTypes.Email, "email"],
            emailVerifiedClaimTypes: ["urn:google:email_verified", "email_verified"],
            nameClaimTypes: [ClaimTypes.Name, "name"],
            imageClaimTypes: ["urn:google:picture", "picture"]);

    private static ExternalIdentity BuildGitHubIdentity(ClaimsPrincipal principal, AuthenticationProperties? properties) =>
        BuildIdentity(
            AegisAuthProviders.GitHub,
            principal,
            properties,
            accountIdClaimTypes: [ClaimTypes.NameIdentifier, "id"],
            emailClaimTypes: [ClaimTypes.Email, "email"],
            emailVerifiedClaimTypes: ["urn:github:email_verified", "email_verified"],
            nameClaimTypes: [ClaimTypes.Name, "name", "urn:github:login", "login"],
            imageClaimTypes: ["urn:github:avatar_url", "avatar_url"]);

    private static ExternalIdentity BuildMicrosoftIdentity(ClaimsPrincipal principal, AuthenticationProperties? properties) =>
        BuildIdentity(
            AegisAuthProviders.Microsoft,
            principal,
            properties,
            accountIdClaimTypes: [ClaimTypes.NameIdentifier, "sub"],
            emailClaimTypes: [ClaimTypes.Email, "email", "preferred_username"],
            emailVerifiedClaimTypes: ["email_verified"],
            nameClaimTypes: [ClaimTypes.Name, "name"],
            imageClaimTypes: ["picture"]);

    private static ExternalIdentity BuildAppleIdentity(ClaimsPrincipal principal, AuthenticationProperties? properties) =>
        BuildIdentity(
            AegisAuthProviders.Apple,
            principal,
            properties,
            accountIdClaimTypes: [ClaimTypes.NameIdentifier, "sub"],
            emailClaimTypes: [ClaimTypes.Email, "email", "urn:apple:email"],
            emailVerifiedClaimTypes: ["urn:apple:email_verified", "email_verified"],
            nameClaimTypes: [ClaimTypes.Name, "name", "urn:apple:name"],
            imageClaimTypes: []);

    private static ExternalIdentity BuildIdentity(
        string providerId,
        ClaimsPrincipal principal,
        AuthenticationProperties? properties,
        string[] accountIdClaimTypes,
        string[] emailClaimTypes,
        string[] emailVerifiedClaimTypes,
        string[] nameClaimTypes,
        string[] imageClaimTypes)
    {
        return new ExternalIdentity
        {
            ProviderId = providerId,
            ProviderAccountId = FindFirstValue(principal, accountIdClaimTypes) ?? string.Empty,
            Email = FindFirstValue(principal, emailClaimTypes),
            EmailVerified = GetBooleanClaim(principal, emailVerifiedClaimTypes),
            Name = FindFirstValue(principal, nameClaimTypes),
            Image = FindFirstValue(principal, imageClaimTypes),
            AccessToken = properties?.GetTokenValue("access_token"),
            RefreshToken = properties?.GetTokenValue("refresh_token"),
            AccessTokenExpiresAt = ParseTokenDate(properties?.GetTokenValue("expires_at")),
            RefreshTokenExpiresAt = ParseTokenDate(properties?.GetTokenValue("refresh_token_expires_at")),
            Scope = properties?.GetTokenValue("scope"),
            IdToken = properties?.GetTokenValue("id_token") ?? FindFirstValue(principal, ["urn:aegis:id_token"]),
        };
    }

    private static string? FindFirstValue(ClaimsPrincipal principal, IReadOnlyList<string> claimTypes)
    {
        foreach (var claimType in claimTypes)
        {
            var value = principal.FindFirstValue(claimType);
            if (string.IsNullOrWhiteSpace(value) is false)
            {
                return value;
            }
        }

        return null;
    }

    private static bool GetBooleanClaim(ClaimsPrincipal principal, IReadOnlyList<string> claimTypes) =>
        bool.TryParse(FindFirstValue(principal, claimTypes), out var parsed) && parsed;

    private static DateTime? ParseTokenDate(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return null;
        }

        return DateTime.TryParse(value, CultureInfo.InvariantCulture, DateTimeStyles.AdjustToUniversal, out DateTime parsed)
            ? parsed
            : null;
    }
}

internal sealed record OAuthProviderDefinition(
    string ProviderId,
    string DisplayName,
    string Scheme,
    string OptionName,
    Func<OAuthOptions, OAuthProviderOptions> GetOptions,
    Func<ClaimsPrincipal, AuthenticationProperties?, ExternalIdentity> BuildIdentity);
