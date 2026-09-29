using Aegis.Auth.Entities;

namespace Aegis.Auth.Features.EmailVerification;

public interface IEmailVerificationService
{
    /// <summary>
    /// Issues a verification token for this user and hands it to
    /// <c>EmailVerification.SendVerificationEmail</c>.
    /// </summary>
    Task<Result> SendVerificationEmailAsync(User user, CancellationToken ct = default);

    /// <summary>
    /// Sends a verification email to the unverified account with this email, if any.
    /// Succeeds whether or not such an account exists, so callers cannot use it to enumerate users.
    /// </summary>
    Task<Result> RequestVerificationEmailAsync(string email, CancellationToken ct = default);

    /// <summary>
    /// Redeems a verification token and marks the owning user's email as verified.
    /// The token alone identifies the user, so no session is required.
    /// </summary>
    Task<Result<User>> VerifyEmailAsync(string rawToken, CancellationToken ct = default);

    Task<string> GenerateVerificationTokenAsync(string userId, CancellationToken ct = default);
}
