using Aegis.Auth.Features.Sessions;
using Aegis.Auth.Abstractions;
using Aegis.Auth.Constants;
using Aegis.Auth.Entities;
using Aegis.Auth.Logging;
using Aegis.Auth.Options;

using EmailValidation;

using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;

namespace Aegis.Auth.Features.SignIn
{
    public interface ISignInService
    {
        Task<Result<SignInResult>> SignInEmail(SignInEmailInput input);
    }

    internal sealed class SignInService(AegisAuthOptions options, ILoggerFactory loggerFactory, IAuthDbContext dbContext, ISessionService sessionService) : ISignInService
    {
        private readonly ISessionService _sessionService = sessionService;
        private readonly AegisAuthOptions _options = options;
        private readonly IAuthDbContext _db = dbContext;
        private readonly ILogger _logger = loggerFactory.CreateLogger<SignInService>();

        public async Task<Result<SignInResult>> SignInEmail(SignInEmailInput input)
        {
            _logger.SignInAttemptInitiated();

            if (!_options.EmailAndPassword.Enabled)
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
            if (!EmailValidator.Validate(normalizedEmail))
            {
                _logger.SignInInvalidEmailFormat();
                return Result<SignInResult>.Failure(AuthErrors.Validation.InvalidInput, "Email not valid.");
            }

            // By hashing passwords for invalid emails, we ensure consistent response times to prevent timing attacks from revealing valid email addresses
            User? user = null;
            try
            {
                user = await _db.Users
                    .Include(u => u.Accounts.Where(a => a.ProviderId == "credential"))
                    .FirstOrDefaultAsync(u => u.Email == normalizedEmail);
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
            Account? credentialAccount = user.Accounts.SingleOrDefault();
            if (credentialAccount is null)
            {
                _logger.SignInNoCredentialAccount(user.Id);
                await _options.EmailAndPassword.Password.Hash(input.Password);
                return Result<SignInResult>.Failure(AuthErrors.Identity.InvalidEmailOrPassword, "Invalid email or password.");
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
            if (!isValidPassword)
            {
                _logger.SignInInvalidPassword(user.Id);
                return Result<SignInResult>.Failure(AuthErrors.Identity.InvalidEmailOrPassword, "Invalid email or password.");
            }

            _logger.SignInPasswordVerified(user.Id);

            //* ATM User exists, has password and has typed in a valid password!

            // ═══════════════════════════════════════════════════════════════════════════════
            // EMAIL VERIFICATION - DISABLED FOR v0.1, WILL BE RE-ENABLED IN v0.2
            // ═══════════════════════════════════════════════════════════════════════════════
            // TODO v0.2: Uncomment this entire block for email verification support
            /*
            if (_options.EmailAndPassword.RequireEmailVerification && !user.EmailVerified)
            {
                _logger.SignInEmailNotVerified(user.Id);

                // If we can't send emails, we just dead-end here.
                if (_options.EmailVerification?.SendVerificationEmail is null)
                {
                    _logger.SignInEmailVerificationNotConfigured(user.Id);
                    return Result<SignInResult>.Failure(AuthErrors.Identity.EmailNotVerified, "Email is not verified.");
                }

                var sendOnSignIn = _options.EmailVerification.SendOnSignIn;
                var requireEmailVer = _options.EmailAndPassword.RequireEmailVerification;

                // Logic: Send if explicitly true, OR if null but verification is required globally
                if (sendOnSignIn == true || (sendOnSignIn is null && requireEmailVer == true))
                {
                    _logger.SignInSendingVerificationEmail(user.Id);
                    // TODO: Create verify token here
                    var token = string.Empty;
                    var url = string.Empty;

                    var verificationContext = new SendVerificationEmailContext { Token = token, User = user, Url = url, CallbackUri = input.Callback };
                    await _options.EmailVerification.SendVerificationEmail(verificationContext);

                    _logger.SignInVerificationEmailSent(user.Id);
                    return Result<SignInResult>.Failure(AuthErrors.Identity.EmailNotVerified, "Verification email sent. Please check your inbox.");
                }

                // They are blocked, but we didn't send a new email because of config settings
                _logger.SignInVerificationDisabled(user.Id);
                return Result<SignInResult>.Failure(AuthErrors.Identity.EmailNotVerified, "Email is not verified.");
            }
            */
            // ═══════════════════════════════════════════════════════════════════════════════

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
            Result<Session> session = await _sessionService.CreateSessionAsync(sessionInput);
            if (!session.IsSuccess || session.Value is null)
            {
                _logger.SignInSessionCreationFailed(user.Id);
                return Result<SignInResult>.Failure(AuthErrors.System.FailedToCreateSession, "Failed to create session. Please try again later.");
            }

            _logger.SignInSuccessful(user.Id);

            return new SignInResult { User = user, Session = session.Value };
        }

        // public async Task<Result<User>> SignInSocial(string email, string password, string? callback)
        // {
        //     await _db.SaveChangesAsync();
        //     return null!;
        // }
    }
}