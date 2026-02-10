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

    // Create a test user
    var user = new User
    {
      Id = Guid.NewGuid().ToString(),
      Email = "test@example.com",
      Name = "Test User",
      IsEmailVerified = true,
      Image = "",
      CreatedAt = DateTime.UtcNow,
      UpdatedAt = DateTime.UtcNow
    };

    context.Users.Add(user);

    // Create a credential account with a hashed password
    // Password will be "Password123!"
    var hashedPassword = await options.EmailAndPassword.Password.Hash("Password123!");

    var account = new Account
    {
      Id = Guid.NewGuid().ToString(),
      AccountId = user.Email,
      ProviderId = "credential",
      PasswordHash = hashedPassword,
      UserId = user.Id,
      CreatedAt = DateTime.UtcNow,
      UpdatedAt = DateTime.UtcNow
    };

    context.Accounts.Add(account);

    await context.SaveChangesAsync();
  }
}
