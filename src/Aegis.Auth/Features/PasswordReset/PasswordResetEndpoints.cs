using Aegis.Auth.Abstractions;
using Aegis.Auth.Extensions;
using Aegis.Auth.Infrastructure.Auth;

using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.EntityFrameworkCore;

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

        if (user is null)
            return Results.Ok(new { message = "If email exists, a reset token has been sent" });

        var rawToken = await passwordResetService.GenerateResetTokenAsync(user.Id, ct);

        // TODO: Send email with rawToken
        // For now, return token in response for testing; remove in production
        return Results.Ok(new { token = rawToken });
    }

    private static async Task<IResult> ResetPasswordAsync(
        ResetPasswordRequest req,
        IPasswordResetService passwordResetService,
        IAegisAuthContextAccessor contextAccessor,
        IAuthDbContext dbContext,
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

        // Hash the new password
        var passwordHash = BCrypt.Net.BCrypt.HashPassword(req.NewPassword);

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
