using Aegis.Auth.Abstractions;
using Aegis.Auth.Entities;
using Aegis.Auth.Options;

namespace Aegis.Auth.Services
{
    public class AuthService(IAuthDbContext db, AuthOptions options)
    {
        private readonly IAuthDbContext _db = db;
        private readonly AuthOptions _options = options;

        public async Task<User> RegisterAsync(string email, string password)
        {
            var user = new User
            {
                Email = email
            };

            var account = new Account
            {
                UserId = user.Id,
                ProviderId = "password",
                PasswordHash = BCrypt.Net.BCrypt.EnhancedHashPassword(password, workFactor: 12),
            };

            _db.Users.Add(user);
            _db.Accounts.Add(account);

            await _db.SaveChangesAsync();

            return user;
        }
    }

}