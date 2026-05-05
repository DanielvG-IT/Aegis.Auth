using Aegis.Auth.Extensions;
using Aegis.Auth.Features.SignIn;
using Aegis.Auth.Http.Internal;
using Aegis.Auth.Infrastructure.Cookies;
using Aegis.Auth.Options;

using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.Options;

namespace Aegis.Auth.Http.Features.SignIn;

internal static class SignInEmailEndpoints
{
    public static RouteGroupBuilder MapSignInEmail(this RouteGroupBuilder group)
    {
        group.MapPost("/sign-in/email", SignInEmailAsync)
            .WithName("AegisAuth.SignIn.Email")
            .WithSummary("Sign in with email and password");

        return group;
    }

    private static async Task<IResult> SignInEmailAsync(
        HttpContext httpContext,
        ISignInService signInService,
        SessionCookieHandler cookieHandler,
        IOptions<AegisAuthOptions> optionsAccessor,
        SignInEmailRequest request,
        CancellationToken cancellationToken)
    {
        var emailInput = new SignInEmailInput
        {
            Email = request.Email,
            Password = request.Password,
            RememberMe = request.RememberMe,
            UserAgent = httpContext.GetClientUserAgent(),
            IpAddress = httpContext.GetClientIpAddress(),
        };

        Result<SignInResult> result = await signInService.SignInEmail(emailInput, cancellationToken);
        if (result.IsSuccess is false || result.Value is null)
        {
            return AegisHttpResultMapper.MapError(httpContext, result.ErrorCode, result.Message);
        }

        SignInResult data = result.Value;

        cookieHandler.SetSessionCookie(httpContext, data.Session, data.User, request.RememberMe);

        var validatedCallback = CallbackValidator.Validate(request.Callback, optionsAccessor.Value);
        var shouldRedirect = validatedCallback is not null;
        if (shouldRedirect)
        {
            httpContext.Response.Headers.Location = validatedCallback;
        }

        return Results.Ok(new SignInResponse
        {
            User = data.User.ToDto(),
            Redirect = shouldRedirect,
            Url = validatedCallback,
            Token = optionsAccessor.Value.Session.IncludeTokenInResponse ? data.Session.Token : null,
        });
    }
}
