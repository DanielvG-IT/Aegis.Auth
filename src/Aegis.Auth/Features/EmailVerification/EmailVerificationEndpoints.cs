using Aegis.Auth.Abstractions;
using Aegis.Auth.Constants;
using Aegis.Auth.Entities;
using Aegis.Auth.Features.RateLimit;
using Aegis.Auth.Plugins;

using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;

namespace Aegis.Auth.Features.EmailVerification;

internal static class EmailVerificationEndpoints
{
    public static RouteGroupBuilder MapEmailVerification(this RouteGroupBuilder group)
    {
        group.MapPost("/email-verify/send-token", SendVerificationTokenAsync)
            .WithName("AegisAuth.EmailVerification.SendToken")
            .WithSummary("Send an email verification token")
            .RequireAegisRateLimit("email-verify-send-token");

        group.MapPost("/email-verify/verify", VerifyEmailAsync)
            .WithName("AegisAuth.EmailVerification.Verify")
            .WithSummary("Verify an email address with a token")
            .RequireAegisRateLimit("email-verify");

        return group;
    }

    private static async Task<IResult> SendVerificationTokenAsync(
        HttpContext httpContext,
        IEmailVerificationService emailVerificationService,
        IAegisAuthContextAccessor contextAccessor,
        IAuthDbContext dbContext,
        SendVerificationTokenRequest request,
        CancellationToken cancellationToken)
    {
        AegisAuthContext? context = await contextAccessor.GetCurrentAsync(httpContext, cancellationToken);

        Result result;
        if (context is not null)
        {
            // Signed-in caller: it's their own account, so specific errors are safe to return.
            User? user = await dbContext.Users.FindAsync([context.UserId], cancellationToken);
            if (user is null)
            {
                return AegisResults.Problem(httpContext, AuthErrors.Session.SessionNotFound, "Session user not found.");
            }

            result = await emailVerificationService.SendVerificationEmailAsync(user, cancellationToken);
        }
        else
        {
            result = await emailVerificationService.RequestVerificationEmailAsync(request.Email ?? string.Empty, cancellationToken);
        }

        if (result.IsSuccess is false)
        {
            return AegisResults.Problem(httpContext, result.ErrorCode, result.Message);
        }

        return Results.Ok(new { message = "If the account exists and is not yet verified, a verification email has been sent." });
    }

    private static async Task<IResult> VerifyEmailAsync(
        HttpContext httpContext,
        IEmailVerificationService emailVerificationService,
        VerifyEmailRequest request,
        CancellationToken cancellationToken)
    {
        Result<User> result = await emailVerificationService.VerifyEmailAsync(request.Token, cancellationToken);
        if (result.IsSuccess is false)
        {
            return AegisResults.Problem(httpContext, result.ErrorCode, result.Message);
        }

        return Results.Ok(new { message = "Email verified successfully." });
    }
}
