using Aegis.Auth.Abstractions;
using Aegis.Auth.Constants;
using Aegis.Auth.Entities;
using Aegis.Auth.Features.EmailVerification;
using Aegis.Auth.Features.RateLimit;
using Aegis.Auth.Features.Sessions;
using Aegis.Auth.Logging;
using Aegis.Auth.Options;

using EmailValidation;

using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Aegis.Auth.Features.SignIn
{
    public interface ISignInService
    {
        Task<Result<SignInResult>> SignInEmail(SignInEmailInput input, CancellationToken cancellationToken = default);
    }

    internal sealed class SignInService(IOptions<AegisAuthOptions> optionsAccessor, ILoggerFactory loggerFactory, IAuthDbContext dbContext, ISessionService sessionService, IEmailVerificationService emailVerificationService, IRateLimitService rateLimitService, TimeProvider timeProvider) : ISignInService
    {
        private readonly ISessionService _sessionService = sessionService;
        private readonly IEmailVerificationService _emailVerificationService = emailVerificationService;
        private readonly IRateLimitService _rateLimitService = rateLimitService;
        private readonly AegisAuthOptions _options = optionsAccessor.Value;
        private readonly IAuthDbContext _db = dbContext;
        private readonly ILogger _logger = loggerFactory.CreateLogger<SignInService>();
        private readonly TimeProvider _time = timeProvider;

        public async Task<Result<SignInResult>> SignInEmail(SignInEmailInput input, CancellationToken cancellationToken = default)
        {
            _logger.SignInAttemptInitiated();

            if (_options.EmailAndPassword.Enabled is false)
            {
                _logger.SignInFeatureDisabled();
                return Result<SignInResult>.Failure(AuthErrors.System.FeatureDisabled, "Password auth is disabled.");
            }

            if (string.IsNullOrWhiteSpace(input.Email))
            {
                _logger.SignInEmailMissing();
                return Result<SignInResult>.Failure(AuthErrors.Validation.InvalidInput, "Email is required.");
            }

            var normalizedEmail = input.Email.Trim().ToLowerInvariant();
            if (EmailValidator.Validate(normalizedEmail) is false)
            {
                _logger.SignInInvalidEmailFormat();
                return Result<SignInResult>.Failure(AuthErrors.Validation.InvalidInput, "Email not valid.");
            }

            // Every attempt counts, not just failures: consuming the permit up front is atomic, so parallel
            // requests cannot all slip past the check before a failure is recorded. Checked before the user
            // lookup so the response is identical for existing and unknown emails.
            if (_rateLimitService.TryAcquireForEmail(normalizedEmail).IsAllowed is false)
            {
                _logger.SignInRateLimited();
                return Result<SignInResult>.Failure(AuthErrors.RateLimit.TooManyRequests, "Too many sign-in attempts. Please try again later.");
            }

            // By hashing passwords for invalid emails, we ensure consistent response times to prevent timing attacks from revealing valid email addresses
            User? user = null;
            try
            {
                user = await _db.Users
                    .Include(u => u.Accounts.Where(a => a.ProviderId == "credential"))
                    .FirstOrDefaultAsync(u => u.Email == normalizedEmail, cancellationToken);
                _logger.SignInDatabaseLookupCompleted();
            }
            catch (Exception ex)
            {
                _logger.SignInDatabaseLookupError(ex);
                return Result<SignInResult>.Failure(AuthErrors.System.InternalError, "Database lookup failed.");
            }

            if (user is null)
            {
                _logger.SignInUserNotFound();
                await _options.EmailAndPassword.Password.Hash(input.Password);
                return Result<SignInResult>.Failure(AuthErrors.Identity.InvalidEmailOrPassword, "Invalid email or password.");
            }

            // Already filtered to credential accounts in the Include above
            Account? credentialAccount = user.Accounts.FirstOrDefault();
            if (credentialAccount is null)
            {
                _logger.SignInNoCredentialAccount(user.Id);
                await _options.EmailAndPassword.Password.Hash(input.Password);
                return Result<SignInResult>.Failure(AuthErrors.Identity.InvalidEmailOrPassword, "Invalid email or password.");
            }

            AccountLockoutOptions lockout = _options.AccountLockout;
            if (lockout.Enabled && user.LockoutUntil > _time.GetUtcNow().UtcDateTime)
            {
                _logger.SignInAccountLocked(user.Id);
                // Hash anyway so a locked account costs the same time as a wrong password.
                await _options.EmailAndPassword.Password.Hash(input.Password);
                return Result<SignInResult>.Failure(AuthErrors.Identity.AccountLocked, "Account is locked. Try again later.");
            }

            var currentPassword = credentialAccount.PasswordHash;
            if (string.IsNullOrWhiteSpace(currentPassword))
            {
                _logger.SignInPasswordHashMissing(user.Id);
                await _options.EmailAndPassword.Password.Hash(input.Password);
                return Result<SignInResult>.Failure(AuthErrors.Identity.InvalidEmailOrPassword, "Invalid email or password.");
            }

            var verifyInput = new PasswordVerifyContext { Hash = currentPassword, Password = input.Password };
            var isValidPassword = await _options.EmailAndPassword.Password.Verify(verifyInput);
            if (isValidPassword is false)
            {
                _logger.SignInInvalidPassword(user.Id);
                if (lockout.Enabled)
                {
                    await RecordFailedSignInAsync(user, lockout, cancellationToken);
                }

                return Result<SignInResult>.Failure(AuthErrors.Identity.InvalidEmailOrPassword, "Invalid email or password.");
            }

            _logger.SignInPasswordVerified(user.Id);

            if (user.FailedSignInCount != 0 || user.LockoutUntil is not null)
            {
                user.FailedSignInCount = 0;
                user.LockoutUntil = null;
                await _db.SaveChangesAsync(cancellationToken);
            }

            //* ATM User exists, has password and has typed in a valid password!

            if (_options.EmailAndPassword.RequireEmailVerification && user.EmailVerified is false)
            {
                _logger.SignInEmailNotVerified(user.Id);

                // If we can't send emails, we just dead-end here.
                if (_options.EmailVerification.SendVerificationEmail is null)
                {
                    _logger.SignInEmailVerificationNotConfigured(user.Id);
                    return Result<SignInResult>.Failure(AuthErrors.Identity.EmailNotVerified, "Email is not verified.");
                }

                // Only reached while RequireEmailVerification is on, so null means "send".
                if (_options.EmailVerification.SendOnSignIn ?? true)
                {
                    _logger.SignInSendingVerificationEmail(user.Id);
                    Result sent = await _emailVerificationService.SendVerificationEmailAsync(user, cancellationToken);
                    if (sent.IsSuccess)
                    {
                        _logger.SignInVerificationEmailSent(user.Id);
                        return Result<SignInResult>.Failure(AuthErrors.Identity.EmailNotVerified, "Email is not verified. A verification email has been sent.");
                    }
                }
                else
                {
                    _logger.SignInVerificationDisabled(user.Id);
                }

                return Result<SignInResult>.Failure(AuthErrors.Identity.EmailNotVerified, "Email is not verified.");
            }

            //* User exists and is all correct state to finalize login

            _logger.SignInCreatingSession(user.Id);

            var sessionInput = new SessionCreateInput
            {
                DontRememberMe = !input.RememberMe,
                IpAddress = input.IpAddress,
                UserAgent = input.UserAgent,
                User = user
            };

            // Create and save session
            Result<Session> session = await _sessionService.CreateSessionAsync(sessionInput, cancellationToken);
            if (session.IsSuccess is false || session.Value is null)
            {
                _logger.SignInSessionCreationFailed(user.Id);
                return Result<SignInResult>.Failure(AuthErrors.System.FailedToCreateSession, "Failed to create session. Please try again later.");
            }

            _logger.SignInSuccessful(user.Id);

            return new SignInResult { User = user, Session = session.Value, CallbackUrl = input.Callback };
        }

        private async Task RecordFailedSignInAsync(User user, AccountLockoutOptions lockout, CancellationToken cancellationToken)
        {
            // Atomic increment and read-back: parallel wrong-password attempts must each count toward the lockout.
            IQueryable<User> row = _db.Users.Where(u => u.Id == user.Id);
            await row.ExecuteUpdateAsync(s => s.SetProperty(u => u.FailedSignInCount, u => u.FailedSignInCount + 1), cancellationToken);
            var failedCount = await row.Select(u => u.FailedSignInCount).FirstAsync(cancellationToken);

            if (failedCount >= lockout.MaxFailedAttempts)
            {
                DateTime lockoutUntil = lockout.PermanentLockout ? DateTime.MaxValue : _time.GetUtcNow().UtcDateTime.Add(lockout.LockoutDuration);
                // Conditional, so of several attempts crossing the threshold together only one applies the lock.
                // The counter starts fresh once the lock expires, instead of re-locking on the next single failure.
                var locked = await row
                    .Where(u => u.FailedSignInCount >= lockout.MaxFailedAttempts)
                    .ExecuteUpdateAsync(s => s
                        .SetProperty(u => u.LockoutUntil, lockoutUntil)
                        .SetProperty(u => u.FailedSignInCount, 0), cancellationToken);
                if (locked > 0)
                {
                    _logger.SignInAccountLockedOut(user.Id, failedCount);
                }
            }

            // ExecuteUpdate bypasses the change tracker; refresh the tracked instance so later reads in this scope see the new state.
            if (_db is DbContext context)
            {
                await context.Entry(user).ReloadAsync(cancellationToken);
            }
        }

        // public async Task<Result<User>> SignInSocial(string email, string password, string? callback)
        // {
        //     await _db.SaveChangesAsync();
        //     return null!;
        // }
    }
}
