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
        Task<Result<User>> SignUpEmail(string email, string password);
    }

    internal sealed class SignUpService(AegisAuthOptions options, ILoggerFactory loggerFactory, IAuthDbContext dbContext) : ISignUpService
    {
        private readonly IAuthDbContext _db = dbContext;
        private readonly AegisAuthOptions _options = options;
        private readonly ILogger _logger = loggerFactory.CreateLogger<SignUpService>();

        public async Task<Result<User>> SignUpEmail(string email, string password)
        {
            _logger.SignUpAttemptInitiated();

            if (!_options.EmailAndPassword.Enabled)
            {
                _logger.SignUpFeatureDisabled();
                return Result<User>.Failure(AuthErrors.System.FeatureDisabled, "Password auth is disabled.");
            }

            if (string.IsNullOrWhiteSpace(email))
            {
                _logger.SignUpEmailMissing();
                return Result<User>.Failure(AuthErrors.Validation.InvalidInput, "Email is required.");
            }

            if (password.Length < _options.EmailAndPassword.MinPasswordLength)
            {
                _logger.SignUpPasswordTooShort(_options.EmailAndPassword.MinPasswordLength);
                return Result<User>.Failure(AuthErrors.Validation.PasswordTooWeak, "Password is too short.");
            }

            var normalizedEmail = email.Trim().ToLowerInvariant();
            if (!EmailValidator.Validate(normalizedEmail))
            {
                _logger.SignUpInvalidEmailFormat();
                return Result<User>.Failure(AuthErrors.Validation.InvalidInput, "Email not valid.");
            }

            var exists = await _db.Users.AsNoTracking().AnyAsync(u => u.Email == normalizedEmail);
            if (exists)
            {
                _logger.SignUpEmailAlreadyExists();
                return Result<User>.Failure(AuthErrors.Identity.UserAlreadyExists, "Email already registered.");
            }

            _logger.SignUpCreatingUser();

            DateTime now = DateTime.UtcNow;
            var user = new User
            {
                Id = Guid.CreateVersion7().ToString(),
                Email = normalizedEmail,
                CreatedAt = now,
                UpdatedAt = now
            };
            var account = new Account
            {
                Id = Guid.CreateVersion7().ToString(),
                AccountId = normalizedEmail,
                UserId = user.Id,
                ProviderId = "credential",
                PasswordHash = await _options.EmailAndPassword.Password.Hash(password),
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
                return user;
            }
            catch (Exception ex)
            {
                _logger.SignUpDatabaseSaveError(ex);
                return Result<User>.Failure(AuthErrors.System.InternalError, "Save failed.");
            }
        }
    }
}