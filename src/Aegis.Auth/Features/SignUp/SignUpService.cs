using Aegis.Auth.Abstractions;
using Aegis.Auth.Constants;
using Aegis.Auth.Entities;
using Aegis.Auth.Options;

using EmailValidation;

using Microsoft.EntityFrameworkCore;

namespace Aegis.Auth.Features.SignUp
{
    public interface ISignUpService
    {
        Task<Result<User>> SignUpEmail(string email, string password);
    }

    internal sealed class SignUpService(AegisAuthOptions options, IAegisLogger logger, IAuthDbContext dbContext) : ISignUpService
    {
        private readonly IAuthDbContext _db = dbContext;
        private readonly AegisAuthOptions _options = options;
        private readonly IAegisLogger _logger = logger;

        public async Task<Result<User>> SignUpEmail(string email, string password)
        {
            if (!_options.EmailAndPassword.Enabled)
                return Result<User>.Failure(AuthErrors.System.FeatureDisabled, "Password auth is disabled.");

            if (string.IsNullOrWhiteSpace(email))
                return Result<User>.Failure(AuthErrors.Validation.InvalidInput, "Email is required.");

            if (password.Length < _options.EmailAndPassword.MinPasswordLength)
                return Result<User>.Failure(AuthErrors.Validation.PasswordTooWeak, "Password is too short.");

            var normalizedEmail = email.Trim().ToLowerInvariant();
            if (!EmailValidator.Validate(normalizedEmail))
                return Result<User>.Failure(AuthErrors.Validation.InvalidInput, "Email not valid.");

            var exists = await _db.Users.AsNoTracking().AnyAsync(u => u.Email == normalizedEmail);
            if (exists)
                return Result<User>.Failure(AuthErrors.Identity.UserAlreadyExists, "Email already registered.");

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
                return user;
            }
            catch (Exception)
            {
                return Result<User>.Failure(AuthErrors.System.InternalError, "Save failed.");
            }
        }
    }
}