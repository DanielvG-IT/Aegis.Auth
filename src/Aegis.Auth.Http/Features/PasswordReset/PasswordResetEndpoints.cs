using Aegis.Auth.Features.PasswordReset;
using Aegis.Auth.Http.Internal;
using Aegis.Auth.Infrastructure.Cookies;
using Aegis.Auth.Options;

using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.Options;

namespace Aegis.Auth.Http.Features.PasswordReset;

internal static class PasswordResetEndpoints
{
    public static RouteGroupBuilder MapPasswordReset(this RouteGroupBuilder group)
    {
        group.MapPost("/password-reset/send-token", SendPasswordResetTokenAsync)
            .WithName("AegisAuth.PasswordReset.SendToken")
            .WithSummary("Send a password reset token to the account's email");

        group.MapPost("/password-reset/reset", ResetPasswordAsync)
            .WithName("AegisAuth.PasswordReset.Reset")
            .WithSummary("Reset password with a token");

        return group;
    }

    private static async Task<IResult> SendPasswordResetTokenAsync(
        HttpContext httpContext,
        IPasswordResetService passwordResetService,
        SendPasswordResetTokenRequest request,
        CancellationToken cancellationToken)
    {
        Result result = await passwordResetService.RequestPasswordResetAsync(request.Email, cancellationToken);
        if (result.IsSuccess is false)
        {
            return AegisHttpResultMapper.MapError(httpContext, result.ErrorCode, result.Message);
        }

        // Same response whether or not the account exists, to prevent user enumeration.
        return Results.Ok(new { message = "If an account with that email exists, a reset link has been sent." });
    }

    private static async Task<IResult> ResetPasswordAsync(
        HttpContext httpContext,
        IPasswordResetService passwordResetService,
        SessionCookieHandler cookieHandler,
        IOptions<AegisAuthOptions> optionsAccessor,
        ResetPasswordRequest request,
        CancellationToken cancellationToken)
    {
        Result result = await passwordResetService.ResetPasswordAsync(request.Token, request.NewPassword, cancellationToken);
        if (result.IsSuccess is false)
        {
            return AegisHttpResultMapper.MapError(httpContext, result.ErrorCode, result.Message);
        }

        if (optionsAccessor.Value.EmailAndPassword.RevokeSessionsOnPasswordReset)
        {
            cookieHandler.ClearSessionCookies(httpContext);
        }

        return Results.Ok(new { message = "Password reset successfully." });
    }
}
