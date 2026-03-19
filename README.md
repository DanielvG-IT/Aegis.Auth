# Aegis.Auth

Modular authentication library for .NET, inspired by BetterAuth (TypeScript).

## Features

- User management (register, login, sessions)
- Password, passkeys, TOTP, OAuth support
- Hooks system (OnUserCreated, OnEmailVerified, etc.)
- Modular architecture (core + HTTP endpoints + optional plugins)
- Designed for extensibility and clean Program.cs integration

## Google OAuth

Google OAuth now uses ASP.NET Core's OAuth middleware for the protocol flow while Aegis still owns account linking and session cookies.

```csharp
builder.Services.AddAegisAuth<AppDbContext>(options =>
{
  options.AppName = "MyApp";
  options.BaseURL = "https://localhost:5001";
  options.Secret = "replace-with-a-32-char-secret-at-minimum";

  options.OAuth.AddGoogle(
    clientId: builder.Configuration["AegisAuth:OAuth:Google:ClientId"]!,
    clientSecret: builder.Configuration["AegisAuth:OAuth:Google:ClientSecret"]!);
});
```

If you prefer property configuration:

```csharp
options.OAuth.Google.Enabled = true;
options.OAuth.Google.ClientId = "...";
options.OAuth.Google.ClientSecret = "...";
```

For OAuth apps, remember to add:

```csharp
app.UseAuthentication();
app.UseAuthorization();
```

The Google Console redirect URI should match `AegisAuthOptions.OAuth.Google.CallbackPath`.

## Getting Started

Clone the repo:

```bash
git clone https://github.com/DanielvG-IT/Aegis.Auth.git
cd Aegis.Auth
```

Open in Visual Studio / Rider / VS Code:

```bash
dotnet restore
dotnet build

```

## Project Structure

```
src/
  Aegis.Auth/
  Aegis.Auth.Http/
  Aegis.Auth.Totp/
  Aegis.Auth.Passkeys/

tests/
  Aegis.Auth.Tests/
```

## Contributing

PRs welcome! Please follow the .editorconfig and add tests for new features.

## Extending The Database Model

Library consumers should own their application's DbContext and implement `IAuthDbContext`.
This lets them use Aegis auth tables plus any app-specific tables in one model.

```csharp
using Aegis.Auth.Abstractions;
using Aegis.Auth.Entities;
using Aegis.Auth.Extensions;

using Microsoft.EntityFrameworkCore;

public sealed class AppDbContext(DbContextOptions<AppDbContext> options)
  : DbContext(options), IAuthDbContext
{
  // Required by Aegis.Auth
  public DbSet<User> Users => Set<User>();
  public DbSet<Account> Accounts => Set<Account>();
  public DbSet<Session> Sessions => Set<Session>();

  // Your app tables
  public DbSet<Project> Projects => Set<Project>();
  public DbSet<ProjectMember> ProjectMembers => Set<ProjectMember>();

  protected override void OnModelCreating(ModelBuilder modelBuilder)
  {
    base.OnModelCreating(modelBuilder);

    // Adds Aegis.Auth indexes and relationships
    modelBuilder.ApplyAegisAuthModel();

    // Configure your app entities
    modelBuilder.Entity<Project>(entity =>
    {
      entity.HasKey(p => p.Id);
      entity.HasOne<User>()
        .WithMany()
        .HasForeignKey(p => p.OwnerUserId)
        .OnDelete(DeleteBehavior.Restrict);
    });
  }
}
```

This pattern keeps Aegis isolated while giving app teams full freedom to add business tables, relationships, and migrations.
