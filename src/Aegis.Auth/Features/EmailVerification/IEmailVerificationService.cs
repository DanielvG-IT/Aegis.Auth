namespace Aegis.Auth.Features.EmailVerification;

public interface IEmailVerificationService
{
    Task<string> GenerateVerificationTokenAsync(string userId, CancellationToken ct = default);
    Task<bool> VerifyEmailAsync(string userId, string rawToken, CancellationToken ct = default);
    Task MarkEmailVerifiedAsync(string userId, CancellationToken ct = default);
}
