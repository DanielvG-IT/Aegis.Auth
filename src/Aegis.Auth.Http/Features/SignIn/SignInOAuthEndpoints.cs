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
    public static RouteGroupBuilder MapOAuth(this RouteGroupBuilder group)
    {
        group.MapGet("/sign-in/oauth/{provider}", StartOAuthAsync)
            .WithName("AegisAuth.SignIn.OAuth")
            .WithSummary("Start external OAuth sign-in");

        group.MapGet("/sign-in/oauth/{provider}/callback", CompleteOAuthAsync)
            .WithName("AegisAuth.SignIn.OAuth.Callback")
            .WithSummary("Complete external OAuth sign-in");

        return group;
    }

    private static IResult StartOAuthAsync(
        HttpContext httpContext,
        IOptions<AegisAuthOptions> optionsAccessor,
        string provider,
        [AsParameters] OAuthChallengeRequest request)
    {
        AegisAuthOptions options = optionsAccessor.Value;

        if (!TryResolveEnabledProvider(httpContext, options, provider, out OAuthProviderDefinition? providerDefinition, out IResult? errorResult))
        {
            return errorResult!;
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

        return Results.Challenge(properties, [providerDefinition!.Scheme]);
    }

    private static async Task<IResult> CompleteOAuthAsync(
        HttpContext httpContext,
        IOAuthService oauthService,
        SessionCookieHandler cookieHandler,
        IOptions<AegisAuthOptions> optionsAccessor,
        string provider,
        [AsParameters] OAuthChallengeRequest request,
        CancellationToken cancellationToken)
    {
        AegisAuthOptions options = optionsAccessor.Value;
        if (!TryResolveEnabledProvider(httpContext, options, provider, out OAuthProviderDefinition? providerDefinition, out IResult? errorResult))
        {
            return errorResult!;
        }

        AuthenticateResult authResult = await httpContext.AuthenticateAsync(AegisAuthSchemes.ExternalCookie);
        if (!authResult.Succeeded || authResult.Principal is null)
        {
            await httpContext.SignOutAsync(AegisAuthSchemes.ExternalCookie);
            return AegisHttpResultMapper.MapError(
                httpContext,
                AuthErrors.Identity.InvalidCredentials,
                $"{providerDefinition!.DisplayName} authentication did not complete successfully.");
        }

        ExternalIdentity identity = providerDefinition!.BuildIdentity(authResult.Principal, authResult.Properties);

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

        var validatedCallback = CallbackValidator.Validate(request.Callback, options);
        var shouldRedirect = validatedCallback is not null;
        if (shouldRedirect)
        {
            return Results.Redirect(validatedCallback!);
        }

        return Results.Ok(new SignInResponse
        {
            User = data.User.ToDto(),
            Redirect = false,
            Url = null,
            Token = options.Session.IncludeTokenInResponse ? data.Session.Token : null,
        });
    }

    private static bool TryResolveEnabledProvider(
        HttpContext httpContext,
        AegisAuthOptions options,
        string provider,
        out OAuthProviderDefinition? providerDefinition,
        out IResult? errorResult)
    {
        errorResult = null;

        if (options.OAuth.Enabled is false)
        {
            providerDefinition = null;
            errorResult = AegisHttpResultMapper.MapError(httpContext, AuthErrors.System.FeatureDisabled, "OAuth is disabled.");
            return false;
        }

        if (!OAuthProviderCatalog.TryGet(provider, out providerDefinition))
        {
            errorResult = AegisHttpResultMapper.MapError(
                httpContext,
                AuthErrors.System.ProviderNotFound,
                $"OAuth provider '{provider}' is not supported.");
            return false;
        }

        if (providerDefinition is null || providerDefinition.GetOptions(options.OAuth).Enabled is false)
        {
            errorResult = AegisHttpResultMapper.MapError(
                httpContext,
                AuthErrors.System.FeatureDisabled,
                $"{providerDefinition?.DisplayName ?? "Requested"} OAuth is disabled.");
            return false;
        }

        return true;
    }
    internal sealed class OAuthChallengeRequest
    {
        public string? Callback { get; init; }
        public bool RememberMe { get; init; } = true;
    }
}
