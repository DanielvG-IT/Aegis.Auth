using Aegis.Auth.Extensions;
using Aegis.Auth.Features.SignUp;
using Aegis.Auth.Http.Internal;
using Aegis.Auth.Infrastructure.Cookies;
using Aegis.Auth.Options;

using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.Options;

namespace Aegis.Auth.Http.Features.SignUp;

internal static class SignUpEmailEndpoints
{
    public static RouteGroupBuilder MapSignUpEmail(this RouteGroupBuilder group)
    {
        group.MapPost("/sign-up/email", SignUpEmailAsync)
            .WithName("AegisAuth.SignUp.Email")
            .WithSummary("Sign up with email and password");

        return group;
    }

    private static async Task<IResult> SignUpEmailAsync(
        HttpContext httpContext,
        ISignUpService signUpService,
        SessionCookieHandler cookieHandler,
        IOptions<AegisAuthOptions> optionsAccessor,
        SignUpEmailRequest request,
        CancellationToken cancellationToken)
    {
        var emailInput = new SignUpEmailInput
        {
            Name = request.Name,
            Image = request.Image,
            Email = request.Email,
            Password = request.Password,
            UserAgent = httpContext.GetClientUserAgent(),
            IpAddress = httpContext.GetClientIpAddress(),
        };

        Result<SignUpResult> result = await signUpService.SignUpEmail(emailInput, cancellationToken);
        if (result.IsSuccess is false || result.Value is null)
        {
            return AegisHttpResultMapper.MapError(httpContext, result.ErrorCode, result.Message);
        }

        SignUpResult data = result.Value;

        if (data.Session is not null)
        {
            cookieHandler.SetSessionCookie(httpContext, data.Session, data.User, rememberMe: false);
        }

        var validatedCallback = CallbackValidator.Validate(request.Callback, optionsAccessor.Value);
        var shouldRedirect = validatedCallback is not null;
        if (shouldRedirect)
        {
            httpContext.Response.Headers.Location = validatedCallback;
        }

        return Results.Ok(new SignUpResponse
        {
            User = data.User.ToDto(),
            Redirect = shouldRedirect,
            Url = validatedCallback,
            Token = optionsAccessor.Value.Session.IncludeTokenInResponse ? data.Session?.Token : null,
        });
    }
}
