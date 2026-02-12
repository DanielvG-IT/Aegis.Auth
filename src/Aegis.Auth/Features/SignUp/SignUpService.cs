using Aegis.Auth.Features.Sessions;
using Aegis.Auth.Abstractions;
using Aegis.Auth.Constants;
using Aegis.Auth.Entities;
using Aegis.Auth.Logging;
using Aegis.Auth.Options;

using EmailValidation;

using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;

namespace Aegis.Auth.Features.SignUp
{
    public interface ISignUpService
    {
        Task<Result<SignUpResult>> SignUpEmail(SignUpEmailInput input);
    }

    internal sealed partial class SignUpService(AegisAuthOptions options, ILoggerFactory loggerFactory, IAuthDbContext dbContext, ISessionService sessionService) : ISignUpService
    {
        private readonly IAuthDbContext _db = dbContext;
        private readonly AegisAuthOptions _options = options;
        private readonly ISessionService _sessionService = sessionService;
        private readonly ILogger _logger = loggerFactory.CreateLogger<SignUpService>();

        public async Task<Result<SignUpResult>> SignUpEmail(SignUpEmailInput input)
        {
            _logger.SignUpAttemptInitiated();

            if (_options.EmailAndPassword.Enabled is false || _options.EmailAndPassword.DisableSignUp is true)
            {
                _logger.SignUpFeatureDisabled();
                return Result<SignUpResult>.Failure(AuthErrors.System.FeatureDisabled, "Password auth is disabled.");
            }

            if (string.IsNullOrWhiteSpace(input.Email) || string.IsNullOrWhiteSpace(input.Password))
            {
                _logger.SignUpInputMissing();
                return Result<SignUpResult>.Failure(AuthErrors.Validation.InvalidInput, "Email and password are required.");
            }

            var normalizedEmail = input.Email.Trim().ToLowerInvariant();
            if (EmailValidator.Validate(normalizedEmail) is false)
            {
                _logger.SignUpInvalidEmailFormat();
                return Result<SignUpResult>.Failure(AuthErrors.Validation.InvalidInput, "Email is not valid.");
            }

            if (input.Password.Length < _options.EmailAndPassword.MinPasswordLength)
            {
                _logger.SignUpPasswordTooShort(_options.EmailAndPassword.MinPasswordLength);
                return Result<SignUpResult>.Failure(AuthErrors.Validation.PasswordTooShort, "Password is too short.");
            }
            if (input.Password.Length > _options.EmailAndPassword.MaxPasswordLength)
            {
                _logger.SignUpPasswordTooLong(_options.EmailAndPassword.MaxPasswordLength);
                return Result<SignUpResult>.Failure(AuthErrors.Validation.PasswordTooLong, "Password is too long.");
            }

            // Custom password validation
            if (_options.EmailAndPassword.Password.Validate is not null)
            {
                var validationContext = new PasswordValidateContext { Password = input.Password, };
                PasswordValidationResult validationResult = await _options.EmailAndPassword.Password.Validate(validationContext);
                if (validationResult.IsValid is false)
                {
                    _logger.SignUpPasswordValidationFailed();
                    return Result<SignUpResult>.Failure(AuthErrors.Validation.InvalidInput, validationResult.ErrorMessage ?? "Password validation failed.");
                }
            }

            var exists = await _db.Users.AsNoTracking().AnyAsync(u => u.Email == normalizedEmail);
            if (exists)
            {
                _logger.SignUpEmailAlreadyExists();
                return Result<SignUpResult>.Failure(AuthErrors.Identity.UserAlreadyExists, "User already exists. Use another email.");
            }

            _logger.SignUpCreatingUser();

            DateTime now = DateTime.UtcNow;
            var hashedPassword = await _options.EmailAndPassword.Password.Hash(input.Password);
            var user = new User
            {
                Id = Guid.CreateVersion7().ToString(),
                Name = input.Name,
                Email = normalizedEmail,
                Image = input.Image,
                CreatedAt = now,
                UpdatedAt = now
            };
            var account = new Account
            {
                Id = Guid.CreateVersion7().ToString(),
                AccountId = normalizedEmail,
                UserId = user.Id,
                ProviderId = "credential",
                PasswordHash = hashedPassword,
                CreatedAt = now,
                UpdatedAt = now
            };

            // TODO: Run applicable hook
            // _options.Hooks.OnUserCreated(); or _options.EmailAndPassword.Hooks.OnUserCreated();

            _db.Users.Add(user);
            _db.Accounts.Add(account);

            try
            {
                await _db.SaveChangesAsync();
                _logger.SignUpSuccessful(user.Id);
            }
            catch (DbUpdateException ex)
            {
                var message = ex.InnerException?.Message?.ToLower() ?? "";
                if (message.Contains("unique") || message.Contains("duplicate") || message.Contains("constraint"))
                {
                    _logger.SignUpDuplicateKeyError(ex);
                    return Result<SignUpResult>.Failure(AuthErrors.Identity.UserAlreadyExists, "User already exists.");
                }

                _logger.SignUpDatabaseSaveError(ex);
                return Result<SignUpResult>.Failure(AuthErrors.System.InternalError, "Creating user failed.");
            }
            catch (Exception ex)
            {
                _logger.SignUpDatabaseSaveError(ex);
                return Result<SignUpResult>.Failure(AuthErrors.System.InternalError, "Creating user failed.");
            }

            /*
                        var shouldSendVerificationEmail = _options.EmailVerification.SendOnSignUp is true ?? _options.EmailAndPassword.RequireEmailVerification is true;
                        if (shouldSendVerificationEmail is true)
                        {
                            // If we can't send emails, we just dead-end here.
                            if (_options.EmailVerification?.SendVerificationEmail is null)
                            {
                                _logger.SignInEmailVerificationNotConfigured(user.Id);
                                return Result<SignUpResult>.Failure(AuthErrors.Identity.EmailNotVerified, "Email is not verified.");
                            }

                            var sendOnSignIn = _options.EmailVerification.SendOnSignUp;
                            var requireEmailVer = _options.EmailAndPassword.RequireEmailVerification;

                            var emailVerifytoken = await _emailService.CreateEmailVerificationToken(_options.Secret, user.Email, null, _options.EmailVerification?.ExpiresIn);

                        }
            */

            Session? session = null;
            var shouldAutoSignIn = _options.EmailAndPassword.AutoSignIn is true; // && _options.EmailAndPassword.RequireEmailVerification is false; TODO Add this in v0.2
            if (shouldAutoSignIn is true)
            {
                var sessionInput = new SessionCreateInput
                {
                    User = user,
                    IpAddress = input.IpAddress,
                    UserAgent = input.UserAgent,
                    DontRememberMe = true
                };
                session = (await _sessionService.CreateSessionAsync(sessionInput)).Value;
            }

            return new SignUpResult { User = user, Session = session, CallbackUrl = input.Callback };
        }
    }
}