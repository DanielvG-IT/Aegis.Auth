using Aegis.Auth.Abstractions;
using Aegis.Auth.Extensions;
using Aegis.Auth.Infrastructure.Auth;

using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;

namespace Aegis.Auth.Features.EmailVerification;

public static class EmailVerificationEndpoints
{
    public static void MapEmailVerificationEndpoints(this IEndpointRouteBuilder routes)
    {
        var group = routes
            .MapGroup("/api/auth/email-verify")
            .WithName("EmailVerification");

        group.MapPost("/send-token", SendVerificationTokenAsync)
            .WithName("SendVerificationToken")
            .WithDescription("Generate and send email verification token");

        group.MapPost("/verify", VerifyEmailAsync)
            .WithName("VerifyEmail")
            .WithDescription("Verify email with token");
    }

    private static async Task<IResult> SendVerificationTokenAsync(
        SendVerificationTokenRequest req,
        IEmailVerificationService emailVerificationService,
        IAegisAuthContextAccessor contextAccessor,
        IAuthDbContext dbContext,
        HttpContext httpContext,
        CancellationToken ct)
    {
        var context = await contextAccessor.GetCurrentAsync(httpContext, ct);
        if (context is null)
            return Results.Unauthorized();

        var user = await dbContext.Users.FindAsync(new object[] { context.UserId }, cancellationToken: ct);
        if (user is null)
            return Results.NotFound();

        if (user.EmailVerified)
            return Results.BadRequest(new { error = "Email already verified" });

        var rawToken = await emailVerificationService.GenerateVerificationTokenAsync(context.UserId, ct);

        // TODO: Send email with rawToken
        // For now, return token in response for testing; remove in production
        return Results.Ok(new { token = rawToken });
    }

    private static async Task<IResult> VerifyEmailAsync(
        VerifyEmailRequest req,
        IEmailVerificationService emailVerificationService,
        IAegisAuthContextAccessor contextAccessor,
        IAuthDbContext dbContext,
        HttpContext httpContext,
        CancellationToken ct)
    {
        var context = await contextAccessor.GetCurrentAsync(httpContext, ct);
        if (context is null)
            return Results.Unauthorized();

        var user = await dbContext.Users.FindAsync(new object[] { context.UserId }, cancellationToken: ct);
        if (user is null)
            return Results.NotFound();

        if (user.EmailVerified)
            return Results.BadRequest(new { error = "Email already verified" });

        var verified = await emailVerificationService.VerifyEmailAsync(context.UserId, req.Token, ct);
        if (!verified)
            return Results.BadRequest(new { error = "Invalid or expired token" });

        await emailVerificationService.MarkEmailVerifiedAsync(context.UserId, ct);
        return Results.Ok(new { message = "Email verified successfully" });
    }
}

public class SendVerificationTokenRequest { }

public class VerifyEmailRequest
{
    public string Token { get; set; } = string.Empty;
}
