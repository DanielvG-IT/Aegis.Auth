using Aegis.Auth.Entities;
using Aegis.Auth.Options;

namespace Aegis.Auth.Sample.Data;

public static class DataSeeder
{
  public static async Task SeedDataAsync(SampleAuthDbContext context, AegisAuthOptions options)
  {
    // Check if we already have data
    if (context.Users.Any())
    {
      return;
    }

    DateTime now = DateTime.UtcNow;

    // Create a test user
    var user = new User
    {
      Id = Guid.CreateVersion7().ToString(),
      Email = "test@example.com",
      Name = "Test User",
      EmailVerified = true,
      Image = "",
      CreatedAt = now,
      UpdatedAt = now
    };

    context.Users.Add(user);

    // Create a credential account with a hashed password
    // Password will be "Password123!"
    var hashedPassword = await options.EmailAndPassword.Password.Hash("Password123!");

    var account = new Account
    {
      Id = Guid.CreateVersion7().ToString(),
      AccountId = user.Email,
      ProviderId = "credential",
      PasswordHash = hashedPassword,
      UserId = user.Id,
      CreatedAt = now,
      UpdatedAt = now
    };

    context.Accounts.Add(account);

    await context.SaveChangesAsync();
  }
}
