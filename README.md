# Aegis.Auth

Modular authentication library for .NET, inspired by BetterAuth (TypeScript).

## Features

- User management (register, login, sessions)
- Password, passkeys, TOTP, OAuth support
- Hooks system (OnUserCreated, OnEmailVerified, etc.)
- Modular architecture (core + HTTP endpoints + optional plugins)
- Designed for extensibility and clean Program.cs integration

## External OAuth Providers

Aegis now ships provider presets for Google, GitHub, Microsoft, and Apple. The protocol flow runs through ASP.NET Core authentication middleware while Aegis still owns account linking and session cookies.

```csharp
builder.Services.AddAegisAuth<AppDbContext>(options =>
{
  options.AppName = "MyApp";
  options.BaseURL = "https://localhost:5001";
  options.Secret = "replace-with-a-32-char-secret-at-minimum";

  options.OAuth.AddGoogle(
    clientId: builder.Configuration["AegisAuth:OAuth:Google:ClientId"]!,
    clientSecret: builder.Configuration["AegisAuth:OAuth:Google:ClientSecret"]!);

  options.OAuth.AddGitHub(
    clientId: builder.Configuration["AegisAuth:OAuth:GitHub:ClientId"]!,
    clientSecret: builder.Configuration["AegisAuth:OAuth:GitHub:ClientSecret"]!);

  options.OAuth.AddMicrosoftEntra(
    clientId: builder.Configuration["AegisAuth:OAuth:MicrosoftEntra:ClientId"]!,
    clientSecret: builder.Configuration["AegisAuth:OAuth:MicrosoftEntra:ClientSecret"]!,
    configure: entra => entra.TenantId = "common");

  options.OAuth.AddApple(
    clientId: builder.Configuration["AegisAuth:OAuth:Apple:ClientId"]!,
    clientSecret: builder.Configuration["AegisAuth:OAuth:Apple:ClientSecret"]!);
});
```

If you prefer property configuration:

```csharp
options.OAuth.Google.Enabled = true;
options.OAuth.Google.ClientId = "...";
options.OAuth.Google.ClientSecret = "...";

options.OAuth.GitHub.Enabled = true;
options.OAuth.GitHub.ClientId = "...";
options.OAuth.GitHub.ClientSecret = "...";

options.OAuth.MicrosoftEntra.Enabled = true;
options.OAuth.MicrosoftEntra.ClientId = "...";
options.OAuth.MicrosoftEntra.ClientSecret = "...";
options.OAuth.MicrosoftEntra.TenantId = "common";

options.OAuth.Apple.Enabled = true;
options.OAuth.Apple.ClientId = "...";
options.OAuth.Apple.ClientSecret = "..."; // pre-generated Apple client secret JWT
```

Provider start routes are:

```text
/api/auth/sign-in/oauth/google
/api/auth/sign-in/oauth/github
/api/auth/sign-in/oauth/microsoft
/api/auth/sign-in/oauth/apple
```

For external auth providers, remember to add:

```csharp
app.UseAuthentication();
app.UseAuthorization();
```

Each provider console should use its matching callback path:

- `AegisAuthOptions.OAuth.Google.CallbackPath`
- `AegisAuthOptions.OAuth.GitHub.CallbackPath`
- `AegisAuthOptions.OAuth.MicrosoftEntra.CallbackPath`
- `AegisAuthOptions.OAuth.Apple.CallbackPath`

Notes:

- GitHub is included because it is a common consumer ask, even though its web sign-in flow is OAuth 2.0 rather than OIDC.
- Microsoft Entra defaults to `TenantId = "common"` so consumers can tighten that to `organizations`, `consumers`, or a specific tenant.
- Apple requires a pre-generated client secret JWT and defaults to `response_mode=form_post`.

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
