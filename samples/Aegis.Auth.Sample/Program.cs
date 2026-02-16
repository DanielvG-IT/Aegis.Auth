using Aegis.Auth.Extensions;
using Aegis.Auth.Options;
using Aegis.Auth.Sample.Data;

using Microsoft.EntityFrameworkCore;

WebApplicationBuilder builder = WebApplication.CreateBuilder(args);

// Add services to the container.

// Configure the database (InMemory for testing)
builder.Services.AddDbContext<SampleAuthDbContext>(options =>
    options.UseInMemoryDatabase("AegisAuthTestDb"));


// Add a memory cache to mock distributed cache
builder.Services.AddDistributedMemoryCache();

// Configure Aegis Auth
builder.Services.AddAegisAuth<SampleAuthDbContext>(options =>
{
    options.AppName = "AegisAuthSample";
    options.BaseURL = "http://localhost:5000";
    options.Secret = "load-this-secret-from-secure-place-like-environment-variables"; // Must be 32 chars or longer

    // Enable email/password authentication
    options.EmailAndPassword.Enabled = true;

    // Configure session
    options.Session.ExpiresIn = 3600; // 1 hour
    options.Session.CookieCache = new CookieCacheOptions
    {
        Enabled = true,
        MaxAge = 300 // 5 minutes
    };
});

builder.Services.AddControllers();
// Learn more about configuring OpenAPI at https://aka.ms/aspnet/openapi
builder.Services.AddOpenApi();

WebApplication app = builder.Build();

// Seed the database
using (IServiceScope scope = app.Services.CreateScope())
{
    SampleAuthDbContext context = scope.ServiceProvider.GetRequiredService<SampleAuthDbContext>();
    AegisAuthOptions options = scope.ServiceProvider.GetRequiredService<Aegis.Auth.Options.AegisAuthOptions>();
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

