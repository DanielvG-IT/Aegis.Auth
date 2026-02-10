using Aegis.Auth.Extensions;
using Aegis.Auth.Sample.Data;

using Microsoft.EntityFrameworkCore;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.

// Configure the database (InMemory for testing)
builder.Services.AddDbContext<SampleAuthDbContext>(options =>
    options.UseInMemoryDatabase("AegisAuthTestDb"));

// Configure Aegis Auth
builder.Services.AddAegisAuth<SampleAuthDbContext>(options =>
{
    options.AppName = "AegisAuthSample";
    options.BaseURL = "http://localhost:5000";
    options.Secret = "your-super-secret-key-minimum-32-characters-long!!!";
    options.LogLevel = Microsoft.Extensions.Logging.LogLevel.Debug;

    // Enable email/password authentication
    options.EmailAndPassword.Enabled = true;
    options.EmailAndPassword.RequireEmailVerification = false; // Disable for testing

    // Configure session
    options.Session.ExpiresIn = 3600; // 1 hour
    options.Session.CookieCache = new Aegis.Auth.Options.CookieCacheOptions
    {
        Enabled = true,
        MaxAge = 300 // 5 minutes
    };
});

builder.Services.AddControllers();
// Learn more about configuring OpenAPI at https://aka.ms/aspnet/openapi
builder.Services.AddOpenApi();

var app = builder.Build();

// Seed the database
using (var scope = app.Services.CreateScope())
{
    var context = scope.ServiceProvider.GetRequiredService<SampleAuthDbContext>();
    var options = scope.ServiceProvider.GetRequiredService<Aegis.Auth.Options.AegisAuthOptions>();
    await DataSeeder.SeedDataAsync(context, options);
}

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.MapOpenApi();
}

app.UseHttpsRedirection();

app.UseAuthorization();

app.MapControllers();

Console.WriteLine("🚀 Aegis Auth Sample API is starting...");
Console.WriteLine("📝 Test credentials:");
Console.WriteLine("   Email: test@example.com");
Console.WriteLine("   Password: Password123!");
Console.WriteLine();

app.Run();

