using Aegis.Auth.Infrastructure.Cookies;
using Aegis.Auth.Features.SignIn;
using Aegis.Auth.Http.Internal;
using Aegis.Auth.Extensions;
using Aegis.Auth.Options;

using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.AspNetCore.Builder;
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

    var validatedCallback = ValidateCallback(request.Callback, optionsAccessor.Value);
    var shouldRedirect = validatedCallback is not null;
    if (shouldRedirect)
    {
      httpContext.Response.Headers.Location = validatedCallback;
    }

    return Results.Ok(new SignInResponse
    {
      User = data.User.ToDto(),
      Token = data.Session.Token,
      Redirect = shouldRedirect,
      Url = validatedCallback,
    });
  }

  private static string? ValidateCallback(string? callback, AegisAuthOptions options)
  {
    if (string.IsNullOrWhiteSpace(callback))
    {
      return null;
    }

    if (callback.StartsWith('/') && !callback.StartsWith("//"))
    {
      return callback;
    }

    if (!Uri.TryCreate(callback, UriKind.Absolute, out Uri? uri))
    {
      return null;
    }

    if (uri.Scheme is not ("http" or "https"))
    {
      return null;
    }

    if (options.TrustedOrigins is null || options.TrustedOrigins.Count == 0)
    {
      return null;
    }

    var origin = $"{uri.Scheme}://{uri.Authority}";
    return options.TrustedOrigins.Contains(origin, StringComparer.OrdinalIgnoreCase) ? callback : null;
  }
}
