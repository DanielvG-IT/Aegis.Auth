using Aegis.Auth.Abstractions;
using Aegis.Auth.Core.Crypto;
using Aegis.Auth.Entities;

using Microsoft.EntityFrameworkCore;

namespace Aegis.Auth.Features.PasswordReset;

internal sealed class PasswordResetService(IAuthDbContext dbContext) : IPasswordResetService
{
    private readonly IAuthDbContext _db = dbContext;
    private const int TokenExpirationMinutes = 30;
    private const string TokenPurpose = "password-reset";

    public async Task<string> GenerateResetTokenAsync(string userId, CancellationToken ct = default)
    {
        var rawToken = AegisCrypto.RandomStringGenerator(32, "a-z", "A-Z", "0-9");
        var now = DateTime.UtcNow;

        var authToken = new AuthToken
        {
            Id = Guid.CreateVersion7().ToString(),
            TokenHash = AegisCrypto.HashToken(rawToken),
            Purpose = TokenPurpose,
            ExpiresAt = now.AddMinutes(TokenExpirationMinutes),
            CreatedAt = now,
            UserId = userId,
        };

        _db.AuthTokens.Add(authToken);
        await _db.SaveChangesAsync(ct);

        return rawToken;
    }

    public async Task<bool> ResetPasswordAsync(string userId, string rawToken, string newPasswordHash, CancellationToken ct = default)
    {
        var tokenHash = AegisCrypto.HashToken(rawToken);
        var now = DateTime.UtcNow;

        var authToken = await _db.AuthTokens.FirstOrDefaultAsync(
            t => t.UserId == userId &&
                 t.TokenHash == tokenHash &&
                 t.Purpose == TokenPurpose,
            ct);

        if (authToken is null)
            return false;

        if (authToken.ExpiresAt < now)
            return false;

        if (authToken.ConsumedAt.HasValue)
            return false;

        // Mark token as consumed
        authToken.ConsumedAt = now;
        _db.AuthTokens.Update(authToken);

        // Update user's password
        var account = await _db.Accounts.FirstOrDefaultAsync(
            a => a.UserId == userId && a.PasswordHash != null,
            ct);

        if (account is not null)
        {
            account.PasswordHash = newPasswordHash;
            account.UpdatedAt = now;
            _db.Accounts.Update(account);
        }

        await _db.SaveChangesAsync(ct);

        return true;
    }
}
