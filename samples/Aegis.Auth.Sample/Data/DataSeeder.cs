using Aegis.Auth.Entities;
using Aegis.Auth.Options;
using Aegis.Auth.Sample.Entities;

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
        var user = new AppUser
        {
            Id = Guid.CreateVersion7().ToString(),
            Email = "test@example.com",
            Name = "Test User",
            EmailVerified = true,
            Image = "",
            IsSpecial = true,
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

        // Create app business data linked to the auth user.
        var project = new Project
        {
            Id = Guid.CreateVersion7().ToString(),
            OwnerUserId = user.Id,
            Name = "Ship Aegis.Auth v0.1",
            Description = "Demo project seeded to show app-specific business logic using Aegis user identity.",
            CreatedAt = now,
            UpdatedAt = now,
        };
        context.Projects.Add(project);

        context.ProjectTasks.AddRange(
            new ProjectTask
            {
                Id = Guid.CreateVersion7().ToString(),
                ProjectId = project.Id,
                Title = "Wire up sign-in and session cookie",
                IsDone = true,
                CreatedAt = now,
                CompletedAt = now,
            },
            new ProjectTask
            {
                Id = Guid.CreateVersion7().ToString(),
                ProjectId = project.Id,
                Title = "Build first business endpoint",
                IsDone = false,
                CreatedAt = now,
                CompletedAt = null,
            });

        await context.SaveChangesAsync();
    }
}
