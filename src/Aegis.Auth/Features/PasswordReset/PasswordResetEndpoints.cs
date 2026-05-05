using Aegis.Auth.Abstractions;
using Aegis.Auth.Extensions;
using Aegis.Auth.Infrastructure.Auth;
using Aegis.Auth.Options;

using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;

namespace Aegis.Auth.Features.PasswordReset;

public static class PasswordResetEndpoints
{
    public static void MapPasswordResetEndpoints(this IEndpointRouteBuilder routes)
    {
        var group = routes
            .MapGroup("/api/auth/password-reset")
            .WithName("PasswordReset");

        group.MapPost("/send-token", SendPasswordResetTokenAsync)
            .WithName("SendPasswordResetToken")
            .WithDescription("Generate and send password reset token");

        group.MapPost("/reset", ResetPasswordAsync)
            .WithName("ResetPassword")
            .WithDescription("Reset password with token");
    }

    private static async Task<IResult> SendPasswordResetTokenAsync(
        SendPasswordResetTokenRequest req,
        IPasswordResetService passwordResetService,
        IAuthDbContext dbContext,
        CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(req.Email))
            return Results.BadRequest(new { error = "Email is required" });

        var user = await dbContext.Users
            .FirstOrDefaultAsync(u => u.Email == req.Email, ct);

        // Always return the same response to prevent user enumeration
        if (user is not null)
        {
            var rawToken = await passwordResetService.GenerateResetTokenAsync(user.Id, ct);
            // TODO: deliver rawToken via email (configure SendPasswordResetEmail delegate in options)
            _ = rawToken;
        }

        return Results.Ok(new { message = "If an account with that email exists, a reset link has been sent." });
    }

    private static async Task<IResult> ResetPasswordAsync(
        ResetPasswordRequest req,
        IPasswordResetService passwordResetService,
        IAegisAuthContextAccessor contextAccessor,
        IOptions<AegisAuthOptions> optionsAccessor,
        HttpContext httpContext,
        CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(req.Token))
            return Results.BadRequest(new { error = "Token is required" });

        if (string.IsNullOrWhiteSpace(req.NewPassword))
            return Results.BadRequest(new { error = "New password is required" });

        var context = await contextAccessor.GetCurrentAsync(httpContext, ct);
        if (context is null)
            return Results.Unauthorized();

        var passwordHash = await optionsAccessor.Value.EmailAndPassword.Password.Hash(req.NewPassword);

        var success = await passwordResetService.ResetPasswordAsync(context.UserId, req.Token, passwordHash, ct);
        if (!success)
            return Results.BadRequest(new { error = "Invalid or expired token" });

        return Results.Ok(new { message = "Password reset successfully" });
    }
}

public class SendPasswordResetTokenRequest
{
    public string Email { get; set; } = string.Empty;
}

public class ResetPasswordRequest
{
    public string Token { get; set; } = string.Empty;
    public string NewPassword { get; set; } = string.Empty;
}
