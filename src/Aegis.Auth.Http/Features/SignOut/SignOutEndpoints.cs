using Aegis.Auth.Infrastructure.Cookies;
using Aegis.Auth.Features.SignOut;
using Aegis.Auth.Http.Internal;

using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.AspNetCore.Builder;

namespace Aegis.Auth.Http.Features.SignOut;

internal static class SignOutEndpoints
{
  public static RouteGroupBuilder MapSignOut(this RouteGroupBuilder group)
  {
    group.MapPost("/sign-out", SignOutAsync)
        .WithName("AegisAuth.SignOut")
        .WithSummary("Sign out and revoke current session");

    return group;
  }

  private static async Task<IResult> SignOutAsync(
      HttpContext httpContext,
      ISignOutService signOutService,
      SessionCookieHandler cookieHandler,
      CancellationToken cancellationToken)
  {
    var token = cookieHandler.GetSessionToken(httpContext);

    cookieHandler.ClearSessionCookies(httpContext);

    if (string.IsNullOrWhiteSpace(token))
    {
      return Results.Ok(new SignOutResponse { Success = true });
    }

    var result = await signOutService.SignOut(new SignOutInput { Token = token }, cancellationToken);
    if (result.IsSuccess is false)
    {
      return AegisHttpResultMapper.MapError(httpContext, result.ErrorCode, result.Message);
    }

    return Results.Ok(new SignOutResponse { Success = true });
  }
}
