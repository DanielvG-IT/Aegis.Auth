using Aegis.Auth.Abstractions;
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

        public async Task<User> RegisterAsync(string email, string password)
        {
            if (!_options.EmailAndPassword.Enabled)
                throw new InvalidOperationException("Password authentication is disabled!");

            if (string.IsNullOrWhiteSpace(email))
                throw new ArgumentException("Email is required.");

            if (password.Length < _options.EmailAndPassword.MinPasswordLength ||
                    password.Length > _options.EmailAndPassword.MaxPasswordLength)
            {
                throw new ArgumentException($"Password must be between {_options.EmailAndPassword.MinPasswordLength} and {_options.EmailAndPassword.MaxPasswordLength} characters.");
            }

            var normalizedEmail = email.Trim().ToLowerInvariant();

            var exists = await _db.Users.AnyAsync(u => u.Email == normalizedEmail);
            if (exists)
            {
                Console.WriteLine("Lilbro is definitely here.");
            }

            var user = new User
            {
                Id = Guid.NewGuid().ToString(),
                Email = normalizedEmail
            };


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
            }
            catch (Exception ex)
            {
                throw new Exception("Registration failed.", ex);
            }

            return user;
        }
    }

}