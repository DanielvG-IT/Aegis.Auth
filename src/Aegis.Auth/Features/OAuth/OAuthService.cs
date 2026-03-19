using Aegis.Auth.Abstractions;
using Aegis.Auth.Constants;
using Aegis.Auth.Entities;
using Aegis.Auth.Features.Sessions;
using Aegis.Auth.Options;

using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;

namespace Aegis.Auth.Features.OAuth;

public interface IOAuthService
{
    Task<Result<OAuthSignInResult>> SignInExternalAsync(OAuthSignInInput input, CancellationToken cancellationToken = default);
}

internal sealed class OAuthService(IOptions<AegisAuthOptions> optionsAccessor, IAuthDbContext dbContext, ISessionService sessionService) : IOAuthService
{
    private readonly AegisAuthOptions _options = optionsAccessor.Value;
    private readonly IAuthDbContext _db = dbContext;
    private readonly ISessionService _sessionService = sessionService;

    public async Task<Result<OAuthSignInResult>> SignInExternalAsync(OAuthSignInInput input, CancellationToken cancellationToken = default)
    {
        if (_options.OAuth.Enabled is false)
        {
            return Result<OAuthSignInResult>.Failure(AuthErrors.System.FeatureDisabled, "OAuth is disabled.");
        }

        if (!string.Equals(input.Identity.ProviderId, "google", StringComparison.OrdinalIgnoreCase))
        {
            return Result<OAuthSignInResult>.Failure(AuthErrors.System.ProviderNotFound, "OAuth provider not found.");
        }

        if (_options.OAuth.Google.Enabled is false)
        {
            return Result<OAuthSignInResult>.Failure(AuthErrors.System.FeatureDisabled, "Google OAuth is disabled.");
        }

        if (string.IsNullOrWhiteSpace(input.Identity.ProviderAccountId))
        {
            return Result<OAuthSignInResult>.Failure(AuthErrors.Validation.InvalidInput, "Provider account id is required.");
        }

        var normalizedEmail = NormalizeEmail(input.Identity.Email);

        Account? account = await _db.Accounts
            .Include(a => a.User)
            .FirstOrDefaultAsync(
                a => a.ProviderId == input.Identity.ProviderId && a.AccountId == input.Identity.ProviderAccountId,
                cancellationToken);

        User? user = account?.User;
        var createdUser = false;
        var linkedByEmail = false;
        DateTime now = DateTime.UtcNow;

        if (account is null && normalizedEmail is not null && _options.OAuth.AutoLinkByEmail)
        {
            user = await _db.Users
                .FirstOrDefaultAsync(u => u.Email == normalizedEmail, cancellationToken);

            if (user is not null)
            {
                linkedByEmail = true;
                account = CreateAccount(user.Id, input.Identity, now);
                _db.Accounts.Add(account);
            }
        }

        if (account is null)
        {
            if (_options.OAuth.AutoCreateUser is false)
            {
                return Result<OAuthSignInResult>.Failure(AuthErrors.Validation.InvalidInput, "No linked account exists for this provider.");
            }

            if (normalizedEmail is null)
            {
                return Result<OAuthSignInResult>.Failure(AuthErrors.Validation.InvalidInput, "OAuth providers must supply an email address when AutoCreateUser is enabled.");
            }

            user = new User
            {
                Id = Guid.CreateVersion7().ToString(),
                Name = input.Identity.Name ?? normalizedEmail,
                Email = normalizedEmail,
                EmailVerified = input.Identity.EmailVerified,
                Image = input.Identity.Image,
                CreatedAt = now,
                UpdatedAt = now,
            };

            account = CreateAccount(user.Id, input.Identity, now);
            _db.Users.Add(user);
            _db.Accounts.Add(account);
            createdUser = true;
        }
        else
        {
            user ??= await _db.Users.FirstAsync(u => u.Id == account.UserId, cancellationToken);
            UpdateExistingAccount(account, input.Identity, now);

            if (normalizedEmail is not null && string.IsNullOrWhiteSpace(user.Email))
            {
                user.Email = normalizedEmail;
            }

            if (input.Identity.EmailVerified)
            {
                user.EmailVerified = true;
            }

            if (string.IsNullOrWhiteSpace(user.Image) && string.IsNullOrWhiteSpace(input.Identity.Image) is false)
            {
                user.Image = input.Identity.Image;
            }

            user.UpdatedAt = now;
        }

        try
        {
            await _db.SaveChangesAsync(cancellationToken);
        }
        catch (DbUpdateException ex)
        {
            var message = ex.InnerException?.Message?.ToLowerInvariant() ?? string.Empty;
            if (message.Contains("unique") || message.Contains("duplicate") || message.Contains("constraint"))
            {
                return Result<OAuthSignInResult>.Failure(AuthErrors.Identity.UserAlreadyExists, "An account already exists for this identity.");
            }

            return Result<OAuthSignInResult>.Failure(AuthErrors.System.InternalError, "Saving the OAuth account failed.");
        }
        catch
        {
            return Result<OAuthSignInResult>.Failure(AuthErrors.System.InternalError, "Saving the OAuth account failed.");
        }

        Result<Session> session = await _sessionService.CreateSessionAsync(
            new SessionCreateInput
            {
                User = user,
                IpAddress = input.IpAddress,
                UserAgent = input.UserAgent,
                DontRememberMe = !input.RememberMe,
            },
            cancellationToken);

        if (session.IsSuccess is false || session.Value is null)
        {
            return Result<OAuthSignInResult>.Failure(AuthErrors.System.FailedToCreateSession, "Failed to create session.");
        }

        return new OAuthSignInResult
        {
            User = user,
            Session = session.Value,
            Account = account,
            CreatedUser = createdUser,
            LinkedByEmail = linkedByEmail,
            CallbackUrl = input.Callback,
        };
    }

    private static string? NormalizeEmail(string? email)
    {
        if (string.IsNullOrWhiteSpace(email))
        {
            return null;
        }

        return email.Trim().ToLowerInvariant();
    }

    private static Account CreateAccount(string userId, ExternalIdentity identity, DateTime now) =>
        new()
        {
            Id = Guid.CreateVersion7().ToString(),
            UserId = userId,
            ProviderId = identity.ProviderId,
            AccountId = identity.ProviderAccountId,
            AccessToken = identity.AccessToken,
            RefreshToken = identity.RefreshToken,
            AccessTokenExpiresAt = identity.AccessTokenExpiresAt,
            RefreshTokenExpiresAt = identity.RefreshTokenExpiresAt,
            Scope = identity.Scope,
            IdToken = identity.IdToken,
            CreatedAt = now,
            UpdatedAt = now,
        };

    private static void UpdateExistingAccount(Account account, ExternalIdentity identity, DateTime now)
    {
        account.AccessToken = identity.AccessToken;
        account.RefreshToken = identity.RefreshToken;
        account.AccessTokenExpiresAt = identity.AccessTokenExpiresAt;
        account.RefreshTokenExpiresAt = identity.RefreshTokenExpiresAt;
        account.Scope = identity.Scope;
        account.IdToken = identity.IdToken;
        account.UpdatedAt = now;
    }
}
