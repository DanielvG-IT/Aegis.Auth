using System.Security.Claims;

using Aegis.Auth.Constants;
using Aegis.Auth.Infrastructure.Cookies;
using Aegis.Auth.Options;

using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Options;

namespace Aegis.Auth.Features.OAuth;

public static class OAuthEndpoints
{
    public static void MapOAuthEndpoints(this IEndpointRouteBuilder routes)
    {
        var group = routes
            .MapGroup("/api/auth/oauth")
            .WithName("OAuth");

        group.MapGet("/{provider}/callback", HandleOAuthCallbackAsync)
            .WithName("OAuthCallback")
            .WithDescription("OAuth provider callback endpoint");

        group.MapPost("/providers", GetEnabledProvidersAsync)
            .WithName("GetEnabledProviders")
            .WithDescription("Get list of enabled OAuth providers");
    }

    private static async Task<IResult> HandleOAuthCallbackAsync(
        string provider,
        HttpContext httpContext,
        IOAuthService oauthService,
        SessionCookieHandler cookieHandler,
        IOptions<AegisAuthOptions> optionsAccessor,
        CancellationToken ct)
    {
        // Get the result of the OAuth authentication
        var authenticateResult = await httpContext.AuthenticateAsync(GetExternalSchemeName(provider));

        if (!authenticateResult.Succeeded)
            return Results.BadRequest(new { error = "OAuth authentication failed" });

        if (authenticateResult.Principal is null)
            return Results.BadRequest(new { error = "No principal received from provider" });

        // Extract callback URL from state
        var state = httpContext.Request.Query["state"].ToString();
        var callback = state != null ? QueryHelpers.ParseQuery(state).TryGetValue("callback", out var cb) ? cb.ToString() : null : null;

        // Build external identity from claims
        var identity = OAuthProviderCatalog.TryGet(provider, out var providerDef)
            ? providerDef?.BuildIdentity(authenticateResult.Principal, authenticateResult.Properties)
            : null;

        if (identity is null)
            return Results.BadRequest(new { error = $"Unable to extract identity from {provider}" });

        // Call OAuth service to link/create account
        var result = await oauthService.SignInExternalAsync(
            new OAuthSignInInput
            {
                Identity = identity,
                IpAddress = httpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown",
                UserAgent = httpContext.Request.Headers.UserAgent.ToString(),
                RememberMe = true,
                Callback = callback,
            },
            ct);

        if (!result.IsSuccess || result.Value is null)
            return Results.BadRequest(new { error = result.Message });

        // Set session cookie
        cookieHandler.SetSessionCookie(httpContext, result.Value.Session, result.Value.User, rememberMe: true);

        // Redirect to callback URL or default dashboard
        var redirectUrl = result.Value.CallbackUrl ?? "/";
        return Results.Redirect(redirectUrl);
    }

    private static async Task<IResult> GetEnabledProvidersAsync(
        IOAuthService oauthService,
        IOptions<AegisAuthOptions> optionsAccessor)
    {
        var options = optionsAccessor.Value;
        var enabledProviders = OAuthProviderCatalog.All
            .Where(p => p.GetOptions(options.OAuth).Enabled)
            .Select(p => new { id = p.ProviderId, name = p.DisplayName })
            .ToList();

        return Results.Ok(new { providers = enabledProviders });
    }

    private static string GetExternalSchemeName(string provider) =>
        provider switch
        {
            "google" => AegisAuthSchemes.Google,
            "github" => AegisAuthSchemes.GitHub,
            "microsoft" => AegisAuthSchemes.Microsoft,
            "apple" => AegisAuthSchemes.Apple,
            _ => throw new InvalidOperationException($"Unknown OAuth provider: {provider}"),
        };
}
