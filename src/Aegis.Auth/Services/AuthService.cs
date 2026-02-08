using Aegis.Auth.Abstractions;
using Aegis.Auth.Constants;
using Aegis.Auth.Entities;
using Aegis.Auth.Options;

using Microsoft.EntityFrameworkCore;

namespace Aegis.Auth.Services
{
    public class AuthService
    {
        private readonly AuthOptions _options;
        private readonly IAuthDbContext _db;

        public AuthService(AuthOptions options)
        {
            _options = options;
            _db = _options.Database;
        }

        public async Task<Result<User>> RegisterAsync(string email, string password)
        {
            if (!_options.EmailAndPassword.Enabled)
                return Result<User>.Failure(AuthErrors.FeatureDisabled, "Password auth is disabled.");

            if (string.IsNullOrWhiteSpace(email))
                return Result<User>.Failure(AuthErrors.InvalidInput, "Email is required.");

            if (password.Length < _options.EmailAndPassword.MinPasswordLength)
                return Result<User>.Failure(AuthErrors.PasswordTooWeak, "Password is too short.");

            var normalizedEmail = email.Trim().ToLowerInvariant();

            if (await _db.Users.AnyAsync(u => u.Email == normalizedEmail))
                return Result<User>.Failure(AuthErrors.UserAlreadyExists, "Email already registered.");

            var user = new User { Id = Guid.NewGuid().ToString(), Email = normalizedEmail };
            var account = new Account
            {
                UserId = user.Id,
                ProviderId = "password",
                PasswordHash = await _options.EmailAndPassword.Password.Hash(password)
            };

            _db.Users.Add(user);
            _db.Accounts.Add(account);

            try
            {
                await _db.SaveChangesAsync();
                return user;
            }
            catch (Exception)
            {
                return Result<User>.Failure(AuthErrors.InternalError, "Save failed.");
            }
        }
    }
}