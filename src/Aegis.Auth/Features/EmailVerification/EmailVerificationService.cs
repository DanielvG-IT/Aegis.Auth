using Aegis.Auth.Abstractions;
using Aegis.Auth.Core.Crypto;
using Aegis.Auth.Entities;
using Aegis.Auth.Extensions;

using Microsoft.EntityFrameworkCore;

namespace Aegis.Auth.Features.EmailVerification;

internal sealed class EmailVerificationService(IAuthDbContext dbContext) : IEmailVerificationService
{
    private readonly IAuthDbContext _db = dbContext;
    private const int TokenExpirationMinutes = 15;
    private const string TokenPurpose = "email-verification";

    public async Task<string> GenerateVerificationTokenAsync(string userId, CancellationToken ct = default)
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

    public async Task<bool> VerifyEmailAsync(string userId, string rawToken, CancellationToken ct = default)
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

        authToken.ConsumedAt = now;
        _db.AuthTokens.Update(authToken);
        await _db.SaveChangesAsync(ct);

        return true;
    }

    public async Task MarkEmailVerifiedAsync(string userId, CancellationToken ct = default)
    {
        var user = await _db.Users.FirstOrDefaultAsync(u => u.Id == userId, ct);
        if (user is not null)
        {
            user.EmailVerified = true;
            user.UpdatedAt = DateTime.UtcNow;
            _db.Users.Update(user);
            await _db.SaveChangesAsync(ct);
        }
    }
}
