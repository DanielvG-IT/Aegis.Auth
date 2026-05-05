namespace Aegis.Auth.Features.PasswordReset;

public interface IPasswordResetService
{
    Task<string> GenerateResetTokenAsync(string userId, CancellationToken ct = default);
    Task<bool> ResetPasswordAsync(string userId, string rawToken, string newPasswordHash, CancellationToken ct = default);
}
