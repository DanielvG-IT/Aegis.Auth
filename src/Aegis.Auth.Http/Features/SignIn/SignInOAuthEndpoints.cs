using System.Globalization;
using System.Security.Claims;

using Aegis.Auth.Constants;
using Aegis.Auth.Extensions;
using Aegis.Auth.Features.OAuth;
using Aegis.Auth.Features.SignIn;
using Aegis.Auth.Http.Internal;
using Aegis.Auth.Infrastructure.Cookies;
using Aegis.Auth.Options;

using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.Options;

namespace Aegis.Auth.Http.Features.SignIn;

internal static class SignInOAuthEndpoints
{
    public static RouteGroupBuilder MapGoogleOAuth(this RouteGroupBuilder group)
    {
        group.MapGet("/sign-in/oauth/google", StartGoogleOAuthAsync)
            .WithName("AegisAuth.SignIn.Google")
            .WithSummary("Start Google OAuth sign-in");

        group.MapGet("/sign-in/oauth/google/callback", CompleteGoogleOAuthAsync)
            .WithName("AegisAuth.SignIn.Google.Callback")
            .WithSummary("Complete Google OAuth sign-in");

        return group;
    }

    private static IResult StartGoogleOAuthAsync(
        HttpContext httpContext,
        IOptions<AegisAuthOptions> optionsAccessor,
        [AsParameters] OAuthChallengeRequest request)
    {
        AegisAuthOptions options = optionsAccessor.Value;

        if (options.OAuth.Enabled is false || options.OAuth.Google.Enabled is false)
        {
            return AegisHttpResultMapper.MapError(httpContext, AuthErrors.System.FeatureDisabled, "Google OAuth is disabled.");
        }

        List<KeyValuePair<string, string?>> query = [];

        if (string.IsNullOrWhiteSpace(request.Callback) is false)
        {
            query.Add(new KeyValuePair<string, string?>("callback", request.Callback));
        }

        if (!request.RememberMe)
        {
            query.Add(new KeyValuePair<string, string?>("rememberMe", bool.FalseString.ToLowerInvariant()));
        }

        var finalizePath = $"{httpContext.Request.Path}/callback";
        var redirectUri = query.Count > 0
            ? $"{finalizePath}{QueryString.Create(query)}"
            : finalizePath;

        var properties = new AuthenticationProperties
        {
            RedirectUri = redirectUri
        };

        return Results.Challenge(properties, [AegisAuthSchemes.Google]);
    }

    private static async Task<IResult> CompleteGoogleOAuthAsync(
        HttpContext httpContext,
        IOAuthService oauthService,
        SessionCookieHandler cookieHandler,
        IOptions<AegisAuthOptions> optionsAccessor,
        [AsParameters] OAuthChallengeRequest request,
        CancellationToken cancellationToken)
    {
        AuthenticateResult authResult = await httpContext.AuthenticateAsync(AegisAuthSchemes.ExternalCookie);
        if (!authResult.Succeeded || authResult.Principal is null)
        {
            await httpContext.SignOutAsync(AegisAuthSchemes.ExternalCookie);
            return AegisHttpResultMapper.MapError(httpContext, AuthErrors.Identity.InvalidCredentials, "Google authentication did not complete successfully.");
        }

        ExternalIdentity identity = BuildGoogleIdentity(authResult.Principal, authResult.Properties);

        Result<OAuthSignInResult> result = await oauthService.SignInExternalAsync(
            new OAuthSignInInput
            {
                Identity = identity,
                UserAgent = httpContext.GetClientUserAgent(),
                IpAddress = httpContext.GetClientIpAddress(),
                RememberMe = request.RememberMe,
                Callback = request.Callback,
            },
            cancellationToken);

        await httpContext.SignOutAsync(AegisAuthSchemes.ExternalCookie);

        if (result.IsSuccess is false || result.Value is null)
        {
            return AegisHttpResultMapper.MapError(httpContext, result.ErrorCode, result.Message);
        }

        OAuthSignInResult data = result.Value;
        cookieHandler.SetSessionCookie(httpContext, data.Session, data.User, request.RememberMe);

        var validatedCallback = CallbackValidator.Validate(request.Callback, optionsAccessor.Value);
        var shouldRedirect = validatedCallback is not null;
        if (shouldRedirect)
        {
            return Results.Redirect(validatedCallback!);
        }

        return Results.Ok(new SignInResponse
        {
            User = data.User.ToDto(),
            Token = data.Session.Token,
            Redirect = false,
            Url = null,
        });
    }

    private static ExternalIdentity BuildGoogleIdentity(ClaimsPrincipal principal, AuthenticationProperties? properties)
    {
        var emailVerified = bool.TryParse(principal.FindFirstValue("urn:google:email_verified"), out var parsedVerified) && parsedVerified;

        return new ExternalIdentity
        {
            ProviderId = "google",
            ProviderAccountId = principal.FindFirstValue(ClaimTypes.NameIdentifier) ?? string.Empty,
            Email = principal.FindFirstValue(ClaimTypes.Email),
            EmailVerified = emailVerified,
            Name = principal.FindFirstValue(ClaimTypes.Name),
            Image = principal.FindFirstValue("urn:google:picture"),
            AccessToken = properties?.GetTokenValue("access_token"),
            RefreshToken = properties?.GetTokenValue("refresh_token"),
            AccessTokenExpiresAt = ParseTokenDate(properties?.GetTokenValue("expires_at")),
            Scope = properties?.GetTokenValue("scope"),
            IdToken = properties?.GetTokenValue("id_token"),
        };
    }

    private static DateTime? ParseTokenDate(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return null;
        }

        return DateTime.TryParse(value, CultureInfo.InvariantCulture, DateTimeStyles.AdjustToUniversal, out var parsed)
            ? parsed
            : null;
    }

    internal sealed class OAuthChallengeRequest
    {
        public string? Callback { get; init; }
        public bool RememberMe { get; init; } = true;
    }
}
