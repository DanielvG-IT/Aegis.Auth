using Aegis.Auth.Abstractions;
using Aegis.Auth.Constants;
using Aegis.Auth.Core.Crypto;
using Aegis.Auth.Entities;
using Aegis.Auth.Logging;
using Aegis.Auth.Options;

using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Aegis.Auth.Features.EmailVerification;

internal sealed class EmailVerificationService(
    IOptions<AegisAuthOptions> optionsAccessor,
    ILoggerFactory loggerFactory,
    IAuthDbContext dbContext,
    IServiceProvider serviceProvider) : IEmailVerificationService
{
    private readonly AegisAuthOptions _options = optionsAccessor.Value;
    private readonly ILogger _logger = loggerFactory.CreateLogger<EmailVerificationService>();
    private readonly IAuthDbContext _db = dbContext;
    private readonly IServiceProvider _services = serviceProvider;
    internal const string TokenPurpose = "email-verification";

    public async Task<Result> SendVerificationEmailAsync(User user, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(user);

        Func<SendVerificationEmailContext, CancellationToken, Task>? send = _options.EmailVerification.SendVerificationEmail;
        if (send is null)
            return Result.Failure(AuthErrors.System.VerificationEmailNotEnabled, "Email verification is not enabled.");

        if (user.EmailVerified)
            return Result.Failure(AuthErrors.Identity.EmailAlreadyVerified, "Email already verified.");

        var rawToken = await GenerateVerificationTokenAsync(user.Id, ct);
        try
        {
            await send(new SendVerificationEmailContext { User = user, Token = rawToken, Services = _services }, ct);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _logger.EmailVerificationDeliveryFailed(user.Id, ex);
            return Result.Failure(AuthErrors.System.InternalError, "Failed to send verification email.");
        }

        _logger.EmailVerificationTokenSent(user.Id);
        return Result.Success();
    }

    public async Task<Result> RequestVerificationEmailAsync(string email, CancellationToken ct = default)
    {
        if (_options.EmailVerification.SendVerificationEmail is null)
            return Result.Failure(AuthErrors.System.VerificationEmailNotEnabled, "Email verification is not enabled.");

        if (string.IsNullOrWhiteSpace(email))
            return Result.Failure(AuthErrors.Validation.EmailRequired, "Email is required.");

        var normalizedEmail = email.Trim().ToLowerInvariant();
        User? user = await _db.Users.FirstOrDefaultAsync(u => u.Email == normalizedEmail, ct);

        // Unknown, already-verified and failed deliveries all look the same to the caller.
        if (user is not null && user.EmailVerified is false)
            await SendVerificationEmailAsync(user, ct);

        return Result.Success();
    }

    public async Task<Result<User>> VerifyEmailAsync(string rawToken, CancellationToken ct = default)
    {
        if (string.IsNullOrWhiteSpace(rawToken))
            return Result<User>.Failure(AuthErrors.Validation.InvalidInput, "Token is required.");

        var tokenHash = AegisCrypto.HashToken(rawToken);
        var now = DateTime.UtcNow;

        AuthToken? authToken = await _db.AuthTokens.FirstOrDefaultAsync(
            t => t.TokenHash == tokenHash && t.Purpose == TokenPurpose,
            ct);

        if (authToken is null || authToken.ExpiresAt < now || authToken.ConsumedAt.HasValue)
        {
            _logger.EmailVerificationInvalidToken();
            return Result<User>.Failure(AuthErrors.Token.InvalidToken, "Invalid or expired token.");
        }

        User? user = await _db.Users.FirstOrDefaultAsync(u => u.Id == authToken.UserId, ct);
        if (user is null)
        {
            _logger.EmailVerificationInvalidToken();
            return Result<User>.Failure(AuthErrors.Token.InvalidToken, "Invalid or expired token.");
        }

        authToken.ConsumedAt = now;
        user.EmailVerified = true;
        user.UpdatedAt = now;
        await _db.SaveChangesAsync(ct);

        _logger.EmailVerificationSuccessful(user.Id);
        return user;
    }

    public async Task<string> GenerateVerificationTokenAsync(string userId, CancellationToken ct = default)
    {
        var rawToken = AegisCrypto.RandomStringGenerator(32, "a-z", "A-Z", "0-9");
        var now = DateTime.UtcNow;

        // Only the most recently sent link stays valid
        var existing = await _db.AuthTokens
            .Where(t => t.UserId == userId && t.Purpose == TokenPurpose && t.ConsumedAt == null)
            .ToListAsync(ct);
        foreach (var t in existing)
            t.ConsumedAt = now;

        var authToken = new AuthToken
        {
            Id = Guid.CreateVersion7().ToString(),
            TokenHash = AegisCrypto.HashToken(rawToken),
            Purpose = TokenPurpose,
            ExpiresAt = now.AddSeconds(_options.EmailVerification.ExpiresIn),
            CreatedAt = now,
            UserId = userId,
        };

        _db.AuthTokens.Add(authToken);
        await _db.SaveChangesAsync(ct);

        return rawToken;
    }
}
