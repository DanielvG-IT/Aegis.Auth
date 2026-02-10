using Aegis.Auth.Extensions;
using Aegis.Auth.Passkeys.Extensions;
using ExampleApp;
using Microsoft.EntityFrameworkCore;

var builder = WebApplication.CreateBuilder(args);

// ========================================
// Database
// ========================================
builder.Services.AddDbContext<AppDbContext>(options =>
    options.UseNpgsql(builder.Configuration.GetConnectionString("DefaultConnection")));

// ========================================
// Aegis.Auth Configuration
// ========================================
builder.Services
    .AddAegisAuth<AppDbContext>(options =>
    {
      // Core options
      options.AppName = "My Application";
      options.BaseURL = "https://example.com";
      options.Secret = builder.Configuration["Auth:Secret"]!;
      options.TrustedOrigins = ["https://example.com"];

      // Email/Password options
      options.EmailAndPassword.RequireEmailVerification = true;
      options.EmailAndPassword.MinPasswordLength = 12;
    })
    // ========================================
    // Feature: Passkey Authentication
    // ========================================
    .AddPasskeys(passkey =>
    {
      passkey.RelyingPartyName = "My Application";
      passkey.RelyingPartyId = "example.com";
      passkey.RequireUserVerification = true;
      passkey.TimeoutMs = 60000;
    });
// ========================================
// Additional features can be chained:
// ========================================
// .AddTotp(totp => 
// {
//     totp.Issuer = "My Application";
// })
// .AddOAuth(oauth => oauth
//     .AddGoogle("client-id", "client-secret")
//     .AddGitHub("client-id", "client-secret")
// );

builder.Services.AddControllers();

var app = builder.Build();

app.UseHttpsRedirection();
app.MapControllers();

app.Run();
