using Aegis.Auth.Abstractions;
using Aegis.Auth.Extensions;
using Aegis.Auth.Constants;
using Aegis.Auth.Entities;
using Aegis.Auth.Options;
using Aegis.Auth.Models;

using EmailValidation;

using Microsoft.EntityFrameworkCore;

namespace Aegis.Auth.Features.SignIn
{
    public interface ISignInService
    {
        Task<Result<SignInResult>> SignInEmail(string email, string password, string? callback, bool rememberMe = false);
    }

    internal sealed class SignInService(AegisAuthOptions options, IAegisLogger logger, IAuthDbContext dbContext) : ISignInService
    {
        private readonly IAuthDbContext _db = dbContext;
        private readonly AegisAuthOptions _options = options;
        private readonly IAegisLogger _logger = logger;

        public async Task<Result<SignInResult>> SignInEmail(string email, string password, string? callback, bool rememberMe = false)
        {
            _logger.Debug("SignIn attempt initiated for email: {Email}", email?.ToLowerInvariant() ?? "null");

            if (!_options.EmailAndPassword.Enabled)
            {
                _logger.Warning("SignIn attempt blocked: Email/Password authentication is disabled");
                return Result<SignInResult>.Failure(AuthErrors.System.FeatureDisabled, "Password auth is disabled.");
            }

            if (string.IsNullOrWhiteSpace(email))
            {
                _logger.Warning("SignIn attempt failed: Email is missing");
                return Result<SignInResult>.Failure(AuthErrors.Validation.InvalidInput, "Email is required.");
            }

            var normalizedEmail = email.ToLowerInvariant().Trim();
            if (!EmailValidator.Validate(normalizedEmail))
            {
                _logger.Warning("SignIn attempt failed: Invalid email format for {Email}", normalizedEmail);
                return Result<SignInResult>.Failure(AuthErrors.Validation.InvalidInput, "Email not valid.");
            }

            // By hashing passwords for invalid emails, we ensure consistent response times to prevent timing attacks from revealing valid email addresses
            User? user = null;
            try
            {
                user = await _db.Users.Include(u => u.Accounts).FirstOrDefaultAsync(u => u.Email == normalizedEmail);
                _logger.Debug("Database lookup completed for email: {Email}", normalizedEmail);
            }
            catch (Exception ex)
            {
                _logger.Error("SignIn failed: Database lookup error for email {Email}", ex, normalizedEmail);
                return Result<SignInResult>.Failure(AuthErrors.System.InternalError, "Database lookup failed.");
            }

            if (user is null)
            {
                _logger.Warning("SignIn failed: User not found for email {Email}. Performing timing-safe hash.", normalizedEmail);
                await _options.EmailAndPassword.Password.Hash(password);
                return Result<SignInResult>.Failure(AuthErrors.Identity.InvalidEmailOrPassword, "Invalid email or password.");
            }

            Account? credentialAccount = user.Accounts.FirstOrDefault(a => a.ProviderId == "credential");
            if (credentialAccount is null)
            {
                _logger.Warning("SignIn failed: No credential account found for user {UserId}", user.Id);
                await _options.EmailAndPassword.Password.Hash(password);
                return Result<SignInResult>.Failure(AuthErrors.Identity.InvalidEmailOrPassword, "Invalid email or password.");
            }

            var currentPassword = credentialAccount.PasswordHash;
            if (string.IsNullOrWhiteSpace(currentPassword))
            {
                _logger.Warning("SignIn failed: Password hash missing for user {UserId}", user.Id);
                await _options.EmailAndPassword.Password.Hash(password);
                return Result<SignInResult>.Failure(AuthErrors.Identity.InvalidEmailOrPassword, "Invalid email or password.");
            }

            var verifyInput = new PasswordVerifyContext { Hash = currentPassword, Password = password };
            var isValidPassword = await _options.EmailAndPassword.Password.Verify(verifyInput);
            if (!isValidPassword)
            {
                _logger.Warning("SignIn failed: Invalid password for user {UserId}", user.Id);
                return Result<SignInResult>.Failure(AuthErrors.Identity.InvalidEmailOrPassword, "Invalid email or password.");
            }

            _logger.Debug("Password verified successfully for user {UserId}", user.Id);

            //* ATM User exists, has password and has typed in a valid password!

            if (_options.EmailAndPassword.RequireEmailVerification && !user.IsEmailVerified)
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

                    var verificationContext = new SendVerificationEmailContext() { Token = token, User = user, Url = url, CallbackUri = callback };
                    await _options.EmailVerification.SendVerificationEmail(verificationContext);

                    _logger.Info("Verification email sent successfully to user {UserId}", user.Id);
                    return Result<SignInResult>.Failure(AuthErrors.Identity.EmailNotVerified, "Verification email sent. Please check your inbox.");
                }

                // They are blocked, but we didn't send a new email because of config settings
                _logger.Warning("SignIn blocked: Email not verified and SendOnSignIn is disabled for user {UserId}", user.Id);
                return Result<SignInResult>.Failure(AuthErrors.Identity.EmailNotVerified, "Email is not verified.");
            }

            //* User exists and is all correct state to finalize login

            _logger.Debug("Creating session for user {UserId}", user.Id);
            // TODO: Create sessiontoken here
            var session = new Session() { };
            if (session is null)
            {
                _logger.Error("SignIn failed: Session creation failed for user {UserId}", args: user.Id);
                return Result<SignInResult>.Failure(AuthErrors.System.FailedToCreateSession, "Failed to create session.");
            }

            _logger.Info("SignIn successful for user {UserId}", user.Id);


            return new SignInResult() { User = user, Session = session };    //Lilbro is logged in
        }

        // public async Task<Result<User>> SignInSocial(string email, string password, string? callback)
        // {
        //     await _db.SaveChangesAsync();
        //     return null!;
        // }
    }
}