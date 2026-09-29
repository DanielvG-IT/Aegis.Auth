namespace Aegis.Auth.Features.PasswordReset;

public interface IPasswordResetService
{
    /// <summary>
    /// Issues a reset token for the account with this email and hands it to
    /// <c>EmailAndPassword.SendResetPassword</c>. Succeeds whether or not the account
    /// exists, so callers cannot use it to enumerate users.
    /// </summary>
    Task<Result> RequestPasswordResetAsync(string email, CancellationToken ct = default);

    /// <summary>
    /// Redeems a reset token and sets a new password. The token alone identifies the user,
    /// so no session is required.
    /// </summary>
    Task<Result> ResetPasswordAsync(string rawToken, string newPassword, CancellationToken ct = default);

    Task<string> GenerateResetTokenAsync(string userId, CancellationToken ct = default);
}
