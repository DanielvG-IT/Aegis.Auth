using Aegis.Auth.Features.Sessions;
using Aegis.Auth.Abstractions;
using Aegis.Auth.Constants;
using Aegis.Auth.Entities;
using Aegis.Auth.Options;

using EmailValidation;

using Microsoft.EntityFrameworkCore;

namespace Aegis.Auth.Features.SignIn
{
    public interface ISignInService
    {
        Task<Result<SignInResult>> SignInEmail(SignInEmailInput input);
    }

    internal sealed class SignInService(AegisAuthOptions options, IAegisLogger logger, IAuthDbContext dbContext, ISessionService sessionService) : ISignInService
    {
        private readonly ISessionService _sessionService = sessionService;
        private readonly AegisAuthOptions _options = options;
        private readonly IAuthDbContext _db = dbContext;
        private readonly IAegisLogger _logger = logger;

        public async Task<Result<SignInResult>> SignInEmail(SignInEmailInput input)
        {
            _logger.Debug("SignIn attempt initiated for email sign-in.");

            if (!_options.EmailAndPassword.Enabled)
            {
                _logger.Warning("SignIn attempt blocked: Email/Password authentication is disabled");
                return Result<SignInResult>.Failure(AuthErrors.System.FeatureDisabled, "Password auth is disabled.");
            }

            if (string.IsNullOrWhiteSpace(input.Email))
            {
                _logger.Warning("SignIn attempt failed: Email is missing");
                return Result<SignInResult>.Failure(AuthErrors.Validation.InvalidInput, "Email is required.");
            }

            var normalizedEmail = input.Email.Trim().ToLowerInvariant();
            if (!EmailValidator.Validate(normalizedEmail))
            {
                _logger.Warning("SignIn attempt failed: Invalid email format.");
                return Result<SignInResult>.Failure(AuthErrors.Validation.InvalidInput, "Email not valid.");
            }

            // By hashing passwords for invalid emails, we ensure consistent response times to prevent timing attacks from revealing valid email addresses
            User? user = null;
            try
            {
                user = await _db.Users
                    .Include(u => u.Accounts.Where(a => a.ProviderId == "credential"))
                    .FirstOrDefaultAsync(u => u.Email == normalizedEmail);
                _logger.Debug("SignIn database lookup completed for provided email.");
            }
            catch (Exception ex)
            {
                _logger.Error("SignIn failed: Database lookup error for provided email.", ex);
                return Result<SignInResult>.Failure(AuthErrors.System.InternalError, "Database lookup failed.");
            }

            if (user is null)
            {
                _logger.Warning("SignIn failed: User not found for provided email. Performing timing-safe hash.");
                await _options.EmailAndPassword.Password.Hash(input.Password);
                return Result<SignInResult>.Failure(AuthErrors.Identity.InvalidEmailOrPassword, "Invalid email or password.");
            }

            // Already filtered to credential accounts in the Include above
            Account? credentialAccount = user.Accounts.SingleOrDefault();
            if (credentialAccount is null)
            {
                _logger.Warning("SignIn failed: No credential account found for user {UserId}", user.Id);
                await _options.EmailAndPassword.Password.Hash(input.Password);
                return Result<SignInResult>.Failure(AuthErrors.Identity.InvalidEmailOrPassword, "Invalid email or password.");
            }

            var currentPassword = credentialAccount.PasswordHash;
            if (string.IsNullOrWhiteSpace(currentPassword))
            {
                _logger.Warning("SignIn failed: Password hash missing for user {UserId}", user.Id);
                await _options.EmailAndPassword.Password.Hash(input.Password);
                return Result<SignInResult>.Failure(AuthErrors.Identity.InvalidEmailOrPassword, "Invalid email or password.");
            }

            var verifyInput = new PasswordVerifyContext { Hash = currentPassword, Password = input.Password };
            var isValidPassword = await _options.EmailAndPassword.Password.Verify(verifyInput);
            if (!isValidPassword)
            {
                _logger.Warning("SignIn failed: Invalid password for user {UserId}", user.Id);
                return Result<SignInResult>.Failure(AuthErrors.Identity.InvalidEmailOrPassword, "Invalid email or password.");
            }

            _logger.Debug("Password verified successfully for user {UserId}", user.Id);

            //* ATM User exists, has password and has typed in a valid password!

            // ═══════════════════════════════════════════════════════════════════════════════
            // EMAIL VERIFICATION - DISABLED FOR v0.1, WILL BE RE-ENABLED IN v0.2
            // ═══════════════════════════════════════════════════════════════════════════════
            // TODO v0.2: Uncomment this entire block for email verification support
            /*
            if (_options.EmailAndPassword.RequireEmailVerification && !user.EmailVerified)
            {
                _logger.Info("SignIn blocked: Email not verified for user {UserId}", user.Id);

                // If we can't send emails, we just dead-end here.
                if (_options.EmailVerification?.SendVerificationEmail is null)
                {
                    _logger.Error("SignIn failed: Email verification required but SendVerificationEmail is not configured for user {UserId}", args: user.Id);
                    return Result<SignInResult>.Failure(AuthErrors.Identity.EmailNotVerified, "Email is not verified.");
                }

                var sendOnSignIn = _options.EmailVerification.SendOnSignIn;
                var requireEmailVer = _options.EmailAndPassword.RequireEmailVerification;

                // Logic: Send if explicitly true, OR if null but verification is required globally
                if (sendOnSignIn == true || (sendOnSignIn is null && requireEmailVer == true))
                {
                    _logger.Info("Sending verification email to user {UserId}", user.Id);
                    // TODO: Create verify token here
                    var token = string.Empty;
                    var url = string.Empty;

                    var verificationContext = new SendVerificationEmailContext { Token = token, User = user, Url = url, CallbackUri = input.Callback };
                    await _options.EmailVerification.SendVerificationEmail(verificationContext);

                    _logger.Info("Verification email sent successfully to user {UserId}", user.Id);
                    return Result<SignInResult>.Failure(AuthErrors.Identity.EmailNotVerified, "Verification email sent. Please check your inbox.");
                }

                // They are blocked, but we didn't send a new email because of config settings
                _logger.Warning("SignIn blocked: Email not verified and SendOnSignIn is disabled for user {UserId}", user.Id);
                return Result<SignInResult>.Failure(AuthErrors.Identity.EmailNotVerified, "Email is not verified.");
            }
            */
            // ═══════════════════════════════════════════════════════════════════════════════

            //* User exists and is all correct state to finalize login

            _logger.Debug("Creating session for user {UserId}", user.Id);

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
                _logger.Warning("SignIn failed: Failed to create session for user {UserId}", user.Id);
                return Result<SignInResult>.Failure(AuthErrors.System.FailedToCreateSession, "Failed to create session. Please try again later.");
            }

            _logger.Info("SignIn successful for user {UserId}", user.Id);

            return new SignInResult { User = user, Session = session.Value };
        }

        // public async Task<Result<User>> SignInSocial(string email, string password, string? callback)
        // {
        //     await _db.SaveChangesAsync();
        //     return null!;
        // }
    }
}