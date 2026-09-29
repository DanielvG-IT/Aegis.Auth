using Aegis.Auth.Abstractions;
using Aegis.Auth.Constants;
using Aegis.Auth.Core.Crypto;
using Aegis.Auth.Entities;
using Aegis.Auth.Features.Sessions;
using Aegis.Auth.Logging;
using Aegis.Auth.Options;

using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Aegis.Auth.Features.PasswordReset;

internal sealed class PasswordResetService(
    IOptions<AegisAuthOptions> optionsAccessor,
    ILoggerFactory loggerFactory,
    IAuthDbContext dbContext,
    ISessionService sessionService,
    IServiceProvider serviceProvider) : IPasswordResetService
{
    private readonly AegisAuthOptions _options = optionsAccessor.Value;
    private readonly ILogger _logger = loggerFactory.CreateLogger<PasswordResetService>();
    private readonly IAuthDbContext _db = dbContext;
    private readonly ISessionService _sessionService = sessionService;
    private readonly IServiceProvider _services = serviceProvider;
    internal const string TokenPurpose = "password-reset";

    public async Task<Result> RequestPasswordResetAsync(string email, CancellationToken ct = default)
    {
        Func<SendResetPasswordContext, CancellationToken, Task>? send = _options.EmailAndPassword.SendResetPassword;
        if (_options.EmailAndPassword.Enabled is false || send is null)
            return Result.Failure(AuthErrors.System.FeatureDisabled, "Password reset is not enabled.");

        if (string.IsNullOrWhiteSpace(email))
            return Result.Failure(AuthErrors.Validation.EmailRequired, "Email is required.");

        var normalizedEmail = email.Trim().ToLowerInvariant();
        User? user = await _db.Users.FirstOrDefaultAsync(u => u.Email == normalizedEmail, ct);
        var hasCredentialAccount = user is not null
            && await _db.Accounts.AnyAsync(a => a.UserId == user.Id && a.ProviderId == "credential", ct);

        // Same result for unknown emails and OAuth-only accounts to prevent user enumeration.
        if (user is null || hasCredentialAccount is false)
        {
            _logger.PasswordResetNoCredentialAccount();
            return Result.Success();
        }

        var rawToken = await GenerateResetTokenAsync(user.Id, ct);
        try
        {
            await send(new SendResetPasswordContext { User = user, Token = rawToken, Services = _services }, ct);
            _logger.PasswordResetTokenSent(user.Id);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            // Swallowed so a delivery failure is indistinguishable from an unknown email.
            _logger.PasswordResetDeliveryFailed(user.Id, ex);
        }

        return Result.Success();
    }

    public async Task<Result> ResetPasswordAsync(string rawToken, string newPassword, CancellationToken ct = default)
    {
        if (string.IsNullOrWhiteSpace(rawToken))
            return Result.Failure(AuthErrors.Validation.InvalidInput, "Token is required.");

        Result passwordCheck = await ValidateNewPasswordAsync(newPassword);
        if (passwordCheck.IsSuccess is false)
            return passwordCheck;

        var tokenHash = AegisCrypto.HashToken(rawToken);
        var now = DateTime.UtcNow;

        AuthToken? authToken = await _db.AuthTokens.FirstOrDefaultAsync(
            t => t.TokenHash == tokenHash && t.Purpose == TokenPurpose,
            ct);

        if (authToken is null || authToken.ExpiresAt < now || authToken.ConsumedAt.HasValue)
        {
            _logger.PasswordResetInvalidToken();
            return Result.Failure(AuthErrors.Token.InvalidToken, "Invalid or expired token.");
        }

        Account? account = await _db.Accounts.FirstOrDefaultAsync(
            a => a.UserId == authToken.UserId && a.ProviderId == "credential",
            ct);

        if (account is null)
        {
            _logger.PasswordResetInvalidToken();
            return Result.Failure(AuthErrors.Token.InvalidToken, "Invalid or expired token.");
        }

        authToken.ConsumedAt = now;
        account.PasswordHash = await _options.EmailAndPassword.Password.Hash(newPassword);
        account.UpdatedAt = now;
        await _db.SaveChangesAsync(ct);

        if (_options.EmailAndPassword.RevokeSessionsOnPasswordReset)
            await _sessionService.RevokeAllSessionsAsync(authToken.UserId, ct);

        _logger.PasswordResetSuccessful(authToken.UserId);
        return Result.Success();
    }

    public async Task<string> GenerateResetTokenAsync(string userId, CancellationToken ct = default)
    {
        var rawToken = AegisCrypto.RandomStringGenerator(32, "a-z", "A-Z", "0-9");
        var now = DateTime.UtcNow;

        // Invalidate any existing unused reset tokens for this user
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
            ExpiresAt = now.AddSeconds(_options.EmailAndPassword.ResetPasswordTokenExpiresIn),
            CreatedAt = now,
            UserId = userId,
        };

        _db.AuthTokens.Add(authToken);
        await _db.SaveChangesAsync(ct);

        return rawToken;
    }

    private async Task<Result> ValidateNewPasswordAsync(string newPassword)
    {
        EmailAndPasswordOptions emailAndPassword = _options.EmailAndPassword;

        if (string.IsNullOrWhiteSpace(newPassword))
            return Result.Failure(AuthErrors.Validation.InvalidInput, "New password is required.");

        if (newPassword.Length < emailAndPassword.MinPasswordLength)
            return Result.Failure(AuthErrors.Validation.PasswordTooShort, "Password is too short.");

        if (newPassword.Length > emailAndPassword.MaxPasswordLength)
            return Result.Failure(AuthErrors.Validation.PasswordTooLong, "Password is too long.");

        if (emailAndPassword.Password.Validate is not null)
        {
            PasswordValidationResult validation = await emailAndPassword.Password.Validate(new PasswordValidateContext { Password = newPassword });
            if (validation.IsValid is false)
                return Result.Failure(AuthErrors.Validation.InvalidInput, validation.ErrorMessage ?? "Password validation failed.");
        }

        return Result.Success();
    }
}
