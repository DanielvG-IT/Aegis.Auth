using Aegis.Auth.Extensions;
using Aegis.Auth.Http.Extensions;
using Aegis.Auth.Options;
using Aegis.Auth.Sample.Data;
using Aegis.Auth.Sample.Services;

using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;

WebApplicationBuilder builder = WebApplication.CreateBuilder(args);

var configuredSecret =
    builder.Configuration["AegisAuth:Secret"]
    ?? Environment.GetEnvironmentVariable("AEGIS_AUTH_SECRET")
    ?? (builder.Environment.IsDevelopment()
        ? "development-only-secret-change-me-at-least-32-chars"
        : string.Empty);

if (string.IsNullOrWhiteSpace(configuredSecret) || configuredSecret.Length < 32)
{
    throw new InvalidOperationException("Configure AegisAuth:Secret (or AEGIS_AUTH_SECRET) with at least 32 characters.");
}

// Add services to the container.

var connectionString =
    builder.Configuration.GetConnectionString("DefaultConnection")
    ?? "Data Source=aegis-auth-sample.db";

// Configure the database (SQLite for realistic local persistence)
builder.Services.AddDbContext<SampleAuthDbContext>(options =>
    options.UseSqlite(connectionString));


// Add a memory cache to mock distributed cache
builder.Services.AddDistributedMemoryCache();

// Configure Aegis Auth
builder.Services.AddAegisAuth<SampleAuthDbContext>(options =>
{
    options.AppName = "AegisAuthSample";
    options.BaseURL = "http://localhost:5000";
    options.Secret = configuredSecret;

    // Enable email/password authentication
    options.EmailAndPassword.Enabled = true;

    var googleClientId = builder.Configuration["AegisAuth:OAuth:Google:ClientId"];
    var googleClientSecret = builder.Configuration["AegisAuth:OAuth:Google:ClientSecret"];
    if (string.IsNullOrWhiteSpace(googleClientId) is false && string.IsNullOrWhiteSpace(googleClientSecret) is false)
    {
        options.OAuth.AddGoogle(googleClientId, googleClientSecret);
    }

    // Configure session
    options.Session.ExpiresIn = 3600; // 1 hour
    options.Session.CookieCache = new CookieCacheOptions
    {
        Enabled = true,
        MaxAge = 300 // 5 minutes
    };
});

builder.Services.AddControllers();
builder.Services.AddScoped<IProjectWorkspaceService, ProjectWorkspaceService>();
builder.Services.AddProblemDetails();
// Learn more about configuring OpenAPI at https://aka.ms/aspnet/openapi
builder.Services.AddOpenApi();

WebApplication app = builder.Build();

// Seed the database
using (IServiceScope scope = app.Services.CreateScope())
{
    SampleAuthDbContext context = scope.ServiceProvider.GetRequiredService<SampleAuthDbContext>();
    await context.Database.EnsureCreatedAsync();
    AegisAuthOptions options = scope.ServiceProvider.GetRequiredService<IOptions<AegisAuthOptions>>().Value;
    await DataSeeder.SeedDataAsync(context, options);
}

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.MapOpenApi();
}
else
{
    app.UseExceptionHandler();
    app.UseHsts();
}

app.UseHttpsRedirection();

app.UseAuthentication();
app.UseAuthorization();

app.MapControllers();
app.MapAegisAuthEndpoints(options =>
{
    builder.Configuration.GetSection("AegisHttp").Bind(options);
});

// Custom minimal APIs protected by Aegis auth.
app.MapGroup("/api/demo")
    .RequireAegisAuth()
    .MapGet("/me", (HttpContext httpContext) =>
    {
        var authContext = httpContext.GetAegisAuthContext();
        return Results.Ok(new
        {
            authContext!.UserId,
            authContext.SessionToken,
            authContext.ExpiresAt,
            authContext.IsFromCookieCache,
        });
    });

Console.WriteLine("🚀 Aegis Auth Sample API is starting...");
Console.WriteLine("📝 Test credentials:");
Console.WriteLine("   Email: test@example.com");
Console.WriteLine("   Password: Password123!");
Console.WriteLine();

app.Run();
